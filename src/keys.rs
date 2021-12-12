use halo2::{
    poly::commitment::Params as params,
    plonk,
    pasta
};

use pasta_curves::{
    vesta
};

use crate::circuit::{MuxCircuit};

// size of circuit
pub const K: u32 = 4;

#[derive(Debug)]
pub struct VerifyingKey {
    pub params: halo2::poly::commitment::Params<vesta::Affine>,
    pub vk: plonk::VerifyingKey<vesta::Affine>,
}

#[derive(Debug)]
pub struct ProvingKey {
    pub params: params<vesta::Affine>,
    pub pk: plonk::ProvingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn build() -> Self {
        let params = halo2::poly::commitment::Params::new(K);
        let circuit: MuxCircuit<pasta::Fp> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { params, vk }
    }
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build() -> Self {
        let params = halo2::poly::commitment::Params::new(K);
        let circuit: MuxCircuit<pasta::Fp> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { params, pk }
    }
}