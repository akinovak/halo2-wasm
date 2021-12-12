use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter},
    plonk::{Error}
};

mod chip;
pub use chip::{MuxConfig, MuxChip};
use crate::utils::UtilitiesInstructions;


pub trait MuxInstructions<F: FieldExt>: UtilitiesInstructions<F>
{
    fn mux(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Var,
        b: Self::Var,
        selector: Self::Var,
    ) -> Result<Self::Var, Error>;
}