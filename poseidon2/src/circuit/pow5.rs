use std::convert::TryInto;
use std::iter;

use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Cell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};

pub const WIDTH_CHOICES: [usize; 8] = [2, 3, 4, 8, 12, 16, 20, 24];

use super::poseidon::{PoseidonInstructions, PoseidonSpongeInstructions, PaddedWord, PermuteChip};
use super::utils::Var;
use crate::base::primitives::{Absorbing, Domain, Mds, Spec, Squeezing, State};

/// Configuration for a [`Pow5Chip`].
#[derive(Clone, Debug)]
pub struct Pow5Config<F: PrimeField, const WIDTH: usize, const RATE: usize> {
    pub state: [Column<Advice>; WIDTH],
    partial_sbox: Column<Advice>,
    rc_a: [Column<Fixed>; WIDTH],
    pad_fixed: [Column<Fixed>; WIDTH],
    s_full: Selector,
    s_first: Selector,
    s_partial: Selector,
    s_pad_and_add: Selector,

    half_full_rounds: usize,
    full_partial_rounds: usize,
    alpha: [u64; 4],
    round_constants: Vec<[F; WIDTH]>,
    mat_external: Mds<F, WIDTH>,
    mat_internal: Mds<F, WIDTH>,
}

/// A Poseidon chip using an $x^5$ S-Box.
///
/// The chip is implemented using a single round per row for full rounds, and two rounds
/// per row for partial rounds.
#[derive(Clone, Debug)]
pub struct Pow5Chip<F: PrimeField, const WIDTH: usize, const RATE: usize> {
    config: Pow5Config<F, WIDTH, RATE>,
}

impl<F: FromUniformBytes<64> + Ord, const WIDTH: usize, const RATE: usize> Pow5Chip<F, WIDTH, RATE> {
    /// Configures this chip for use in a circuit.
    ///
    /// # Side-effects
    ///
    /// All columns in `state` will be equality-enabled.
    //
    // TODO: Does the rate need to be hard-coded here, or only the width? It probably
    // needs to be known wherever we implement the hashing gadget, but it isn't strictly
    // necessary for the permutation.
    pub fn configure<S: Spec<F, WIDTH, RATE>>(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; WIDTH],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; WIDTH],
        pad_fixed: [Column<Fixed>; WIDTH],
    ) -> Pow5Config<F, WIDTH, RATE> {
        assert_eq!(RATE, WIDTH - 1);
        // Generate constants for the Poseidon permutation.
        // This gadget requires R_F and R_P to be even.
        assert!(S::full_rounds() & 1 == 0);
        assert!(S::partial_rounds() & 1 == 0);
        let half_full_rounds = S::full_rounds() / 2;
        let full_partial_rounds = S::partial_rounds();
        let (round_constants, mat_internal, mat_external) = S::constants();

        // This allows state words to be initialized (by constraining them equal to fixed
        // values), and used in a permutation from an arbitrary region. rc_a is used in
        // every permutation round.
        for column in iter::empty()
            .chain(state.iter().cloned().map(Column::<Any>::from))
            .chain(pad_fixed.iter().cloned().map(Column::<Any>::from))
        {
            meta.enable_equality(column);
        }

        let s_full = meta.selector();
        let s_first = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();

        let alpha = [5, 0, 0, 0];
        let pow_5 = |v: Expression<F>| {
            let v2 = v.clone() * v.clone();
            v2.clone() * v2 * v
        };

        meta.create_gate("first layer", |meta| {
            let s_first = meta.query_selector(s_first);

            Constraints::with_selector(
                s_first,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                state_cur * mat_external[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("full round", |meta| {
            let s_full = meta.query_selector(s_full);

            Constraints::with_selector(
                s_full,
                (0..WIDTH)
                    .map(|next_idx| {
                        let state_next = meta.query_advice(state[next_idx], Rotation::next());
                        let expr = (0..WIDTH)
                            .map(|idx| {
                                let state_cur = meta.query_advice(state[idx], Rotation::cur());
                                let rc_a = meta.query_fixed(rc_a[idx], Rotation::cur());
                                pow_5(state_cur + rc_a) * mat_external[next_idx][idx]
                            })
                            .reduce(|acc, term| acc + term)
                            .expect("WIDTH > 0");
                        expr - state_next
                    })
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("partial rounds", |meta| {
            let cur_0 = meta.query_advice(state[0], Rotation::cur());
            let mid_0 = meta.query_advice(partial_sbox, Rotation::cur());
            let rc_a0 = meta.query_fixed(rc_a[0], Rotation::cur());
            let s_partial = meta.query_selector(s_partial);

            use halo2_proofs::plonk::VirtualCells;
            let mid = |idx: usize, meta: &mut VirtualCells<F>| {
                let mid = mid_0.clone() * mat_internal[idx][0];
                (1..WIDTH).fold(mid, |acc, cur_idx| {
                    let cur = meta.query_advice(state[cur_idx], Rotation::cur());
                    acc + cur * mat_internal[idx][cur_idx]
                })
            };

            let next = |idx: usize, meta: &mut VirtualCells<F>| {
                meta.query_advice(state[idx], Rotation::next())
            };

            let partial_round_linear = |idx: usize, meta: &mut VirtualCells<F>| {
                mid(idx, meta)
            };

            Constraints::with_selector(
                s_partial,
                std::iter::empty()
                    .chain(Some(pow_5(cur_0 + rc_a0) - mid_0.clone()))
                    .chain((0..WIDTH).map(|idx| partial_round_linear(idx, meta) - next(idx, meta)))
                    .collect::<Vec<_>>(),
            )
        });

        meta.create_gate("pad-and-add", |meta| {
            let initial_state_rate = meta.query_advice(state[RATE], Rotation::prev());
            let output_state_rate = meta.query_advice(state[RATE], Rotation::next());
            let s_pad_and_add = meta.query_selector(s_pad_and_add);

            let pad_and_add = |idx: usize| {
                let initial_state = meta.query_advice(state[idx], Rotation::prev());
                let input = meta.query_advice(state[idx], Rotation::cur());
                let output_state = meta.query_advice(state[idx], Rotation::next());

                // We pad the input by storing the required padding in fixed columns and
                // then constraining the corresponding input columns to be equal to it.
                initial_state + input - output_state
            };

            Constraints::with_selector(
                s_pad_and_add,
                (0..RATE)
                    .map(pad_and_add)
                    // The capacity element is never altered by the input.
                    .chain(Some(initial_state_rate - output_state_rate))
                    .collect::<Vec<_>>(),
            )
        });

        Pow5Config {
            state,
            partial_sbox,
            rc_a,
            pad_fixed,
            s_full,
            s_first,
            s_partial,
            s_pad_and_add,
            half_full_rounds,
            full_partial_rounds,
            alpha,
            round_constants,
            mat_external,
            mat_internal,
        }
    }

    /// Construct a [`Pow5Chip`].
    pub fn construct(config: Pow5Config<F, WIDTH, RATE>) -> Self {
        Pow5Chip { config }
    }
}

impl<F:FromUniformBytes<64> + Ord, const WIDTH: usize, const RATE: usize> Chip<F> for Pow5Chip<F, WIDTH, RATE> {
    type Config = Pow5Config<F, WIDTH, RATE>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FromUniformBytes<64> + Ord, S: Spec<F, 3, 2>> PermuteChip<F, S, 3, 2>
    for Pow5Chip<F, 3, 2>
{
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let state = [0; 3].map(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let constants = [0; 6].map(|_| meta.fixed_column());

        Pow5Chip::configure::<S>(
            meta,
            state,
            partial_sbox,
            constants[..3].try_into().unwrap(), //rc_a
            constants[3..].try_into().unwrap(), //rc_b
        )
    }

    fn construct(config: Self::Config) -> Self {
        Self::construct(config)
    }
}

impl<F: FromUniformBytes<64> + Ord, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>
    PoseidonInstructions<F, S, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    type Word = StateWord<F>;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "permute state",
            |mut region| {
                // Load the initial state into this region.
                let state = Pow5State::load(&mut region, config, initial_state)?;
                let state = state.first_layer(&mut region, config)?;
                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| state.full_round(&mut region, config, r, r + 1))
                })?;

                let state = (0..config.full_partial_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.partial_round(
                            &mut region,
                            config,
                            config.half_full_rounds + r,
                            config.half_full_rounds + r + 1,
                        )
                    })
                })?;

                let state = (0..config.half_full_rounds).fold(Ok(state), |res, r| {
                    res.and_then(|state| {
                        state.full_round(
                            &mut region,
                            config,
                            config.half_full_rounds + config.full_partial_rounds + r,
                            config.half_full_rounds + config.full_partial_rounds + r + 1,
                        )
                    })
                })?;

                Ok(state.0)
            },
        )
    }
}

impl<
        F: FromUniformBytes<64> + Ord,
        S: Spec<F, WIDTH, RATE>,
        D: Domain<F, RATE>,
        const WIDTH: usize,
        const RATE: usize,
    > PoseidonSpongeInstructions<F, S, D, WIDTH, RATE> for Pow5Chip<F, WIDTH, RATE>
{
    fn initial_state(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        let state = layouter.assign_region(
            || format!("initial state for domain {}", D::name()),
            |mut region| {
                let mut state = Vec::with_capacity(WIDTH);
                let mut load_state_word = |i: usize, value: F| -> Result<_, Error> {
                    let var = region.assign_advice_from_constant(
                        || format!("state_{}", i),
                        config.state[i],
                        0,
                        value,
                    )?;
                    state.push(StateWord(var));

                    Ok(())
                };

                for i in 0..RATE {
                    load_state_word(i, F::ZERO)?;
                }
                load_state_word(RATE, D::initial_capacity_element())?;

                Ok(state)
            },
        )?;

        Ok(state.try_into().unwrap())
    }

    fn add_input(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
        input: &Absorbing<PaddedWord<F>, RATE>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        let config = self.config();
        layouter.assign_region(
            || format!("add input for domain {}", D::name()),
            |mut region| {
                config.s_pad_and_add.enable(&mut region, 1)?;
                // Load the initial state into this region.
                let load_state_word = |i: usize| {
                    initial_state[i]
                        .0
                        .copy_advice(
                            || format!("load state_{}", i),
                            &mut region,
                            config.state[i],
                            0,
                        )
                        .map(StateWord)
                };
                let initial_state: Result<Vec<_>, Error> =
                    (0..WIDTH).map(load_state_word).collect();
                let initial_state = initial_state?;
                // Load the input into this region.
                let load_input_word = |i: usize| {
                    let (cell, value) = match input.0[i].clone() {
                        Some(PaddedWord::Message(word)) => (word.cell(), word.value().copied()),
                        Some(PaddedWord::Padding(padding_value)) => {
                            let cell = region
                                .assign_fixed(
                                    || format!("load pad_{}", i),
                                    config.pad_fixed[i],
                                    1,
                                    || Value::known(padding_value),
                                )?
                                .cell();
                            (cell, Value::known(padding_value))
                        }
                        _ => panic!("Input is not padded"),
                    };
                    let var = region.assign_advice(
                        || format!("load input_{}", i),
                        config.state[i],
                        1,
                        || value,
                    )?;
                    region.constrain_equal(cell, var.cell())?;

                    Ok(StateWord(var))
                };
                let input: Result<Vec<_>, Error> = (0..RATE).map(load_input_word).collect();
                let input = input?;
                // Constrain the output.
                let constrain_output_word = |i: usize| {
                    let value = initial_state[i].0.value().copied()
                        + input
                            .get(i)
                            .map(|word| word.0.value().cloned())
                            // The capacity element is never altered by the input.
                            .unwrap_or_else(|| Value::known(F::ZERO));
                    region
                        .assign_advice(
                            || format!("load output_{}", i),
                            config.state[i],
                            2,
                            || value,
                        )
                        .map(StateWord)
                };
                let output: Result<Vec<_>, Error> = (0..WIDTH).map(constrain_output_word).collect();
                output.map(|output| output.try_into().unwrap())
            },
        )
    }

    fn get_output(state: &State<Self::Word, WIDTH>) -> Squeezing<Self::Word, RATE> {
        Squeezing(
            state[..RATE]
                .iter()
                .map(|word| Some(word.clone()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

/// A word in the Poseidon state.
#[derive(Clone, Debug)]
pub struct StateWord<F: Field>(AssignedCell<F, F>);

impl<F: Field> From<StateWord<F>> for AssignedCell<F, F> {
    fn from(state_word: StateWord<F>) -> AssignedCell<F, F> {
        state_word.0
    }
}

impl<F: Field> From<AssignedCell<F, F>> for StateWord<F> {
    fn from(cell_value: AssignedCell<F, F>) -> StateWord<F> {
        StateWord(cell_value)
    }
}

impl<F: Field> Var<F> for StateWord<F> {
    fn cell(&self) -> Cell {
        self.0.cell()
    }

    fn value(&self) -> Value<F> {
        self.0.value().cloned()
    }
}

#[derive(Debug)]
struct Pow5State<F: PrimeField, const WIDTH: usize>([StateWord<F>; WIDTH]);

impl<F: PrimeField, const WIDTH: usize> Pow5State<F, WIDTH> {

    fn load<const RATE: usize>(
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        initial_state: &State<StateWord<F>, WIDTH>,
    ) -> Result<Self, Error> {
        let load_state_word = |i: usize| {
            initial_state[i]
                .0
                .copy_advice(|| format!("load state_{}", i), region, config.state[i], 0)
                .map(StateWord)
        };

        let state: Result<Vec<_>, _> = (0..WIDTH).map(load_state_word).collect();
        state.map(|state| Pow5State(state.try_into().unwrap()))
    }

    fn first_layer<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
    ) -> Result<Self, Error> {
        let offset = 0; // first layer
        config.s_first.enable(region, offset)?;
            let q = self.0.iter().map(|word| {
                word.0
                    .value()
                    .map(|v| *v)
            });
            let r: Value<Vec<F>> = q.collect();
            let m = &config.mat_external;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });

            let state: [Value<F>; WIDTH] = state.collect::<Vec<_>>().try_into().unwrap();
            let next_state_word = |i: usize| {
                let value = state[i];
                let var = region.assign_advice(
                    || format!("pre_round state_{}", i),
                    config.state[i],
                    offset + 1,
                    || value,
                )?;
                Ok(StateWord(var))
            };
    
            let next_state: Result<Vec<_>, _> = (0..WIDTH).map(next_state_word).collect();
            next_state.map(|next_state| Pow5State(next_state.try_into().unwrap()))
    }

    fn full_round<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_full, |_| {
            let q = self.0.iter().enumerate().map(|(idx, word)| {
                word.0
                    .value()
                    .map(|v| *v + config.round_constants[round][idx])
            });
            let r: Value<Vec<F>> = q.map(|q| q.map(|q| q.pow(config.alpha))).collect();
            let m = &config.mat_external;
            let state = m.iter().map(|m_i| {
                r.as_ref().map(|r| {
                    r.iter()
                        .enumerate()
                        .fold(F::ZERO, |acc, (j, r_j)| acc + m_i[j] * r_j)
                })
            });

            Ok((round + 1, state.collect::<Vec<_>>().try_into().unwrap()))
        })
    }

    fn partial_round<const RATE: usize>(
        self,
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
    ) -> Result<Self, Error> {
        Self::round(region, config, round, offset, config.s_partial, |region| {
            let m = &config.mat_internal;
            let p: Value<Vec<_>> = self.0.iter().map(|word| word.0.value().cloned()).collect();

            let r: Value<Vec<_>> = p.map(|p| {
                let r_0 = (p[0] + config.round_constants[round][0]).pow(config.alpha);
                let r_i = p[1..]
                    .iter()
                    .copied();
                std::iter::empty().chain(Some(r_0)).chain(r_i).collect()
            });

            region.assign_advice(
                || format!("round_{} partial_sbox", round),
                config.partial_sbox,
                offset,
                || r.as_ref().map(|r| r[0]),
            )?;

            let state: Vec<Value<_>> = m
                .iter()
                .map(|m_i| {
                    r.as_ref().map(|r| {
                        m_i.iter()
                            .zip(r.iter())
                            .fold(F::ZERO, |acc, (m_ij, r_j)| acc + *m_ij * r_j)
                    })
                })
                .collect();

            Ok((round + 1, state.try_into().unwrap()))
        })
    }

    fn round<const RATE: usize>(
        region: &mut Region<F>,
        config: &Pow5Config<F, WIDTH, RATE>,
        round: usize,
        offset: usize,
        round_gate: Selector,
        round_fn: impl FnOnce(&mut Region<F>) -> Result<(usize, [Value<F>; WIDTH]), Error>,
    ) -> Result<Self, Error> {
        // Enable the required gate.
        round_gate.enable(region, offset)?;
        // Load the round constants.
        let mut load_round_constant = |i: usize| {
            region.assign_fixed(
                || format!("round_{} rc_{}", round, i),
                config.rc_a[i],
                offset,
                || Value::known(config.round_constants[round][i]),
            )
        };
        for i in 0..WIDTH {
            load_round_constant(i)?;
        }

        // Compute the next round's state.
        let (next_round, next_state) = round_fn(region)?;

        let next_state_word = |i: usize| {
            let value = next_state[i];
            let var = region.assign_advice(
                || format!("round_{} state_{}", next_round, i),
                config.state[i],
                offset + 1,
                || value,
            )?;
            Ok(StateWord(var))
        };

        let next_state: Result<Vec<_>, _> = (0..WIDTH).map(next_state_word).collect();
        next_state.map(|next_state| Pow5State(next_state.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::Num;
    use ff::{Field, PrimeField};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::bn256::Fr as Fp;
    //use rand::rngs::OsRng;

    use crate::base::primitives::permute;
    use crate::base::P128Pow5T3;

    use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
    use crate::base::primitives::{self as poseidon, ConstantLength, Spec}; // P128Pow5T3 as OrchardNullifier
    use std::convert::TryInto;
    use std::marker::PhantomData;

    struct PermuteCircuit<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>(
        PhantomData<S>,
    );

    impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Circuit<Fp>
        for PermuteCircuit<S, WIDTH, RATE>
    {
        type Config = Pow5Config<Fp, WIDTH, RATE>;
        type FloorPlanner = SimpleFloorPlanner;


        fn without_witnesses(&self) -> Self {
            PermuteCircuit::<S, WIDTH, RATE>(PhantomData)
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, WIDTH, RATE> {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let partial_sbox = meta.advice_column();

            let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            let pad_fixed = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                pad_fixed.try_into().unwrap(),
            )
        }

        fn synthesize(
            &self,
            config: Pow5Config<Fp, WIDTH, RATE>,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let initial_state = layouter.assign_region(
                || "prepare initial state",
                |mut region| {
                    let state_word = |i: usize| {
                        let value = Value::known(Fp::from(i as u64));
                        let var = region.assign_advice(
                            || format!("load state_{}", i),
                            config.state[i],
                            0,
                            || value,
                        )?;
                        Ok(StateWord(var))
                    };

                    let state: Result<Vec<_>, Error> = (0..WIDTH).map(state_word).collect();
                    Ok(state?.try_into().unwrap())
                },
            )?;

            let chip = Pow5Chip::construct(config.clone());
            let final_state = <Pow5Chip<_, WIDTH, RATE> as PoseidonInstructions<
                Fp,
                S,
                WIDTH,
                RATE,
            >>::permute(&chip, &mut layouter, &initial_state)?;

            // For the purpose of this test, compute the real final state inline.
            let mut expected_final_state = (0..WIDTH)
                .map(|idx| Fp::from(idx as u64))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            poseidon::permute::<_, S, WIDTH, RATE>(
                &mut expected_final_state
            );

            println!("expected:{:?}", expected_final_state);

            layouter.assign_region(
                || "constrain final state",
                |mut region| {
                    let mut final_state_word = |i: usize| {
                        let var = region.assign_advice(
                            || format!("load final_state_{}", i),
                            config.state[i],
                            0,
                            || Value::known(expected_final_state[i]),
                        )?;
                        region.constrain_equal(final_state[i].0.cell(), var.cell())
                    };

                    for i in 0..(WIDTH) {
                        final_state_word(i)?;
                    }

                    Ok(())
                },
            )
        }
    }

    #[test]
    fn poseidon_permute() {
        let k = 7;
        let circuit = PermuteCircuit::<P128Pow5T3<Fp>, 3, 2>(PhantomData);

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }

    // struct HashCircuit<
    //     S: Spec<Fp, WIDTH, RATE>,
    //     const WIDTH: usize,
    //     const RATE: usize,
    //     const L: usize,
    // > {
    //     message: Value<[Fp; L]>,
    //     // For the purpose of this test, witness the result.
    //     // TODO: Move this into an instance column.
    //     output: Value<Fp>,
    //     _spec: PhantomData<S>,
    // }

    // impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    //     Circuit<Fp> for HashCircuit<S, WIDTH, RATE, L>
    // {
    //     type Config = Pow5Config<Fp, WIDTH, RATE>;
    //     type FloorPlanner = SimpleFloorPlanner;
    //     // #[cfg(feature = "circuit-params")]
    //     type Params = ();

    //     fn without_witnesses(&self) -> Self {
    //         Self {
    //             message: Value::unknown(),
    //             output: Value::unknown(),
    //             _spec: PhantomData,
    //         }
    //     }

    //     fn configure(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, WIDTH, RATE> {
    //         let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
    //         let partial_sbox = meta.advice_column();

    //         let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
    //         let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

    //         meta.enable_constant(rc_b[0]);

    //         Pow5Chip::configure::<S>(
    //             meta,
    //             state.try_into().unwrap(),
    //             partial_sbox,
    //             rc_a.try_into().unwrap(),
    //             rc_b.try_into().unwrap(),
    //         )
    //     }

    //     fn synthesize(
    //         &self,
    //         config: Pow5Config<Fp, WIDTH, RATE>,
    //         mut layouter: impl Layouter<Fp>,
    //     ) -> Result<(), Error> {
    //         let chip = Pow5Chip::construct(config.clone());

    //         let message = layouter.assign_region(
    //             || "load message",
    //             |mut region| {
    //                 let message_word = |i: usize| {
    //                     let value = self.message.map(|message_vals| message_vals[i]);
    //                     region.assign_advice(
    //                         || format!("load message_{}", i),
    //                         config.state[i],
    //                         0,
    //                         || value,
    //                     )
    //                 };

    //                 let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
    //                 Ok(message?.try_into().unwrap())
    //             },
    //         )?;

    //         let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
    //             chip,
    //             layouter.namespace(|| "init"),
    //         )?;
    //         let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

    //         layouter.assign_region(
    //             || "constrain output",
    //             |mut region| {
    //                 let expected_var = region.assign_advice(
    //                     || "load output",
    //                     config.state[0],
    //                     0,
    //                     || self.output,
    //                 )?;
    //                 region.constrain_equal(output.cell(), expected_var.cell())
    //             },
    //         )
    //     }
    // }

//     #[test]
//     fn poseidon_hash() {
//         let rng = OsRng;

//         let message = [Fp::random(rng), Fp::random(rng)];
//         let output =
//             poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

//         let k = 6;
//         let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
//             message: Value::known(message),
//             output: Value::known(output),
//             _spec: PhantomData,
//         };
//         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//         assert_eq!(prover.verify(), Ok(()))
//     }

//     #[test]
//     fn poseidon_hash_longer_input() {
//         let rng = OsRng;

//         let message = [Fp::random(rng), Fp::random(rng), Fp::random(rng)];
//         let output =
//             poseidon::Hash::<_, OrchardNullifier, ConstantLength<3>, 3, 2>::init().hash(message);

//         let k = 7;
//         let circuit = HashCircuit::<OrchardNullifier, 3, 2, 3> {
//             message: Value::known(message),
//             output: Value::known(output),
//             _spec: PhantomData,
//         };
//         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//         assert_eq!(prover.verify(), Ok(()))
//     }

//     #[test]
//     fn poseidon_hash_longer_input_custom() {
//         let rng = OsRng;

//         let message = [Fp::random(rng), Fp::random(rng), Fp::random(rng), Fp::random(rng)];
//         let output =
//             poseidon::Hash::<_, OrchardNullifier, ConstantLength<4>, 3, 2>::init().hash(message);

//         let k = 7;
//         let circuit = HashCircuit::<OrchardNullifier, 3, 2, 4> {
//             message: Value::known(message),
//             output: Value::known(output),
//             _spec: PhantomData,
//         };
//         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//         assert_eq!(prover.verify(), Ok(()))
//     }

//     #[test]
//     fn hash_test_vectors() {
//         for tv in crate::poseidon::primitives::test_vectors::fp::hash() {
//             let message = [
//                 pallas::Base::from_repr(tv.input[0]).unwrap(),
//                 pallas::Base::from_repr(tv.input[1]).unwrap(),
//             ];
//             let output = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
//                 .hash(message);

//             let k = 6;
//             let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
//                 message: Value::known(message),
//                 output: Value::known(output),
//                 _spec: PhantomData,
//             };
//             let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//             assert_eq!(prover.verify(), Ok(()));
//         }
//     }

//     #[cfg(feature = "test-dev-graph")]
//     #[test]
//     fn print_poseidon_chip() {
//         use plotters::prelude::*;

//         let root = BitMapBackend::new("poseidon-chip-layout.png", (1024, 768)).into_drawing_area();
//         root.fill(&WHITE).unwrap();
//         let root = root
//             .titled("Poseidon Chip Layout", ("sans-serif", 60))
//             .unwrap();

//         let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
//             message: Value::unknown(),
//             output: Value::unknown(),
//             _spec: PhantomData,
//         };
//         halo2_proofs::dev::CircuitLayout::default()
//             .render(6, &circuit, &root)
//             .unwrap();
//     }
// }
}
