use std::{array, marker::PhantomData};

use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, Expression},
    poly::Rotation,
};

use super::MuxInstructions;
use crate::utils::{UtilitiesInstructions, CellValue, copy};

#[derive(Clone, Debug)]
pub struct MuxConfig {
    left: Column<Advice>,
    right: Column<Advice>,
    s: Column<Advice>,
    q_mux: Selector
}

#[derive(Debug)]
pub struct MuxChip<F: FieldExt> {
    pub config: MuxConfig,
    pub _marker: PhantomData<F>,
}

impl<F: FieldExt> MuxChip<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
    ) -> <Self as Chip<F>>::Config {

        for column in &advice {
            meta.enable_equality((*column).into());
        }

        let left = advice[0];
        let right = advice[1];
        let s = advice[2];

        let q_mux = meta.selector();

        meta.create_gate("mux constraint", |meta| {
            let q_mux = meta.query_selector(q_mux);
            let left = meta.query_advice(advice[0], Rotation::cur());
            let right = meta.query_advice(advice[1], Rotation::cur());
            let s = meta.query_advice(advice[2], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());

            let one = Expression::Constant(F::one());

            let bool_check = s.clone() * (one.clone() - s.clone());
            let mux_check = out - right * s.clone() - left * (one - s);

            array::IntoIter::new([bool_check, mux_check])
                .map(move |poly| q_mux.clone() * poly)
        });

        MuxConfig {
            left,
            right,
            s,
            q_mux
        }
    }

    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}
// ANCHOR_END: chip-config

impl<F: FieldExt> UtilitiesInstructions<F> for MuxChip<F> {
    type Var = CellValue<F>;
}


impl<F: FieldExt> Chip<F> for MuxChip<F> {
    type Config = MuxConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> MuxInstructions<F> for MuxChip<F> {
    fn mux(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Var,
        b: Self::Var,
        selector: Self::Var,
    ) -> Result<Self::Var, Error> {
        let config = self.config();

        layouter.assign_region(|| "mux ", 
            |mut region| {
                let mut row_offset = 0;
                config.q_mux.enable(&mut region, 0)?;

                let left = copy(&mut region, || "copy left", config.left, row_offset, &a)?;
                let right = copy(&mut region, || "copy right", config.right, row_offset, &b)?;
                let s = copy(&mut region, || "copy s", config.s, row_offset, &selector)?;

                row_offset += 1;

                let out = {
                    let swapped = 
                        left.value
                        .zip(right.value)
                        .zip(s.value)
                        .map(|((left, right), s)| if s == F::one() { right } else { left });

                    let cell = region.assign_advice(
                        || "witness swapped value",
                        config.left,
                        row_offset,
                        || swapped.ok_or(Error::SynthesisError)
                    )?;

                    CellValue {
                        cell, 
                        value: swapped
                    }
                };

                Ok(out)
            }
        )
    }
}
