use halo2::{
    plonk,
    plonk::{Error},
    pasta,
    transcript::{Blake2bRead, Blake2bWrite},
};

use pasta_curves::{
    vesta
};

use crate::{
    keys::{ProvingKey, VerifyingKey},
    circuit::{MuxCircuit, MUX_OUTPUT},
};

#[derive(Debug, Clone)]
pub struct Proof(Vec<u8>);

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub struct Instance {
    pub result: vesta::Scalar, 
}

impl Instance {
    pub fn to_halo2_instance(&self) -> [[vesta::Scalar; 1]; 1] {
        let mut instance = [vesta::Scalar::zero(); 1];

        instance[MUX_OUTPUT] = self.result;
        [instance]
    }
}

impl Proof {
    /// Creates a proof for the given circuit and instances.
    pub fn create(
        pk: &ProvingKey,
        circuits: &[MuxCircuit<pasta::Fp>],
        instances: &[Instance],
    ) -> Result<Self, Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let public_inputs: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(&pk.params, &pk.pk, &circuits, &public_inputs, &mut transcript)?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Instance]) -> Result<(), plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let msm = vk.params.empty_msm();
        let mut transcript = Blake2bRead::init(&self.0[..]);
        let guard = plonk::verify_proof(&vk.params, &vk.vk, msm, &instances, &mut transcript)?;
        let msm = guard.clone().use_challenges();
        if msm.eval() {
            Ok(())
        } else {
            Err(plonk::Error::ConstraintSystemFailure)
        }
    }

    /// Constructs a new Proof value.
    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use std::iter;
    use halo2::pasta::Fp;
    use halo2::dev::MockProver;

    use crate::circuit::MuxCircuit;
    use crate::keys::{ProvingKey, VerifyingKey, K};

    use super::{Instance, Proof};


    // #[test]
    // fn round_trip() {
    //     let (circuits, instances): (Vec<_>, Vec<_>) = iter::once(())
    //         .map(|()| {
    //             let a = Fp::random(&mut rng);
    //             let b = Fp::random(&mut rng);
    //             let selector = Fp::one;

    //             let result;
    //             if selector == Fp::one() {
    //                 result = b;
    //             } else {
    //                 result = a;
    //             }

    //             (
    //                 MuxCircuit::<Fp> {
    //                     a: Some(a), 
    //                     b: Some(b), 
    //                     selector: Some(selector)
    //                 },
    //                 Instance {
    //                     result
    //                 },
    //             )
    //         })
    //         .unzip();

    //     let vk = VerifyingKey::build();

    //     // Test that the pinned verification key (representing the circuit)
    //     // is as expected.
    //     // {
    //     //     // panic!("{:#?}", vk.vk.pinned());
    //     //     assert_eq!(
    //     //         format!("{:#?}\n", vk.vk.pinned()),
    //     //         include_str!("circuit_description").replace("\r\n", "\n")
    //     //     );
    //     // }

    //     // Test that the proof size is as expected.
    //     // let expected_proof_size = {
    //     //     let circuit_cost = halo2::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(
    //     //         K as usize,
    //     //         &circuits[0],
    //     //     );
    //     //     assert_eq!(usize::from(circuit_cost.proof_size(1)), 4992);
    //     //     assert_eq!(usize::from(circuit_cost.proof_size(2)), 7264);
    //     //     usize::from(circuit_cost.proof_size(instances.len()))
    //     // };

    //     for (circuit, instance) in circuits.iter().zip(instances.iter()) {
    //         assert_eq!(
    //             MockProver::run(
    //                 K,
    //                 circuit,
    //                 instance
    //                     .to_halo2_instance()
    //                     .iter()
    //                     .map(|p| p.to_vec())
    //                     .collect()
    //             )
    //             .unwrap()
    //             .verify(),
    //             Ok(())
    //         );
    //     }

    //     let pk = ProvingKey::build();
    //     let proof = Proof::create(&pk, &circuits, &instances).unwrap();
    //     assert!(proof.verify(&vk, &instances).is_ok());
    //     // assert_eq!(proof.0.len(), expected_proof_size);
    // }


}