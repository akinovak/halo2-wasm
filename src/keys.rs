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

    pub fn export<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.vk.write(writer)
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

// #[cfg(test)]
// mod tests {

//     use super::{VerifyingKey};
//     use halo2::{
//         plonk,
//         pasta
//     };
//     use pasta_curves::vesta;
//     use super::K;
//     use crate::circuit::{MuxCircuit};

//     #[test]
//     fn vk_serialization() {
//         let mut output: Vec<u8> = Vec::new();
//         let vk = VerifyingKey::build();

//         match vk.export(&mut output) {
//             Ok(_) => (),
//             Err(e) => return println!("{}", e.to_string()),
//         };

//         let mut sliced: &[u8] = &output[..];
//         let params = halo2::poly::commitment::Params::new(K);

//         let _retrieved = plonk::VerifyingKey::<vesta::Affine>::read::<_, MuxCircuit<pasta::Fp>>(
//             &mut sliced,
//             &params
//         );
//     }
// }