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
const K: u32 = 3;

#[derive(Debug)]
pub struct VerifyingKey {
    params: halo2::poly::commitment::Params<vesta::Affine>,
    vk: plonk::VerifyingKey<vesta::Affine>,
}

#[derive(Debug)]
pub struct ProvingKey {
    params: params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
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