use halo2::{
    pasta::{Fp},
};

use crate::{
    circuit::MuxCircuit,
    keys::{ProvingKey, VerifyingKey}
};

use crate::proof::{Proof, Instance};
use std::iter;

use wasm_bindgen::prelude::*;
pub use wasm_bindgen_rayon::init_thread_pool;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}


#[wasm_bindgen]
pub struct MuxWasm {
}

/*TODO there is compatibility issue with export and retrieve_vk 
their values are same, just exported has len(160) and retireved(128)
I'll try to solve with clean env & rln

    #[wasm_bindgen]
    pub fn export_verifier_key() -> Result<Vec<u8>, JsValue> {
        set_panic_hook();
        let mut output: Vec<u8> = Vec::new();
        let vk = VerifyingKey::build();
        match vk.export(&mut output) {
            Ok(_) => (),
            Err(e) => return Err(e.to_string().into()),
        };
        Ok(output)
    }

    #[wasm_bindgen]
    pub fn retrieve_vk(mut raw_vk: &[u8]) -> Result<Vec<u8>, JsValue> {
        set_panic_hook();
        let params = halo2::poly::commitment::Params::new(K);
        let plonk_vk = plonk::VerifyingKey::<vesta::Affine>::read::<_, MuxCircuit<pasta::Fp>>(
            &mut raw_vk,
            &params
        ).unwrap();

        let vk = VerifyingKey {
            params, 
            vk: plonk_vk
        };

        let mut output: Vec<u8> = Vec::new();
        match vk.export(&mut output) {
            Ok(_) => (),
            Err(e) => return Err(e.to_string().into()),
        };
        Ok(output)
    }
*/

#[wasm_bindgen]
impl MuxWasm {
    #[wasm_bindgen]
    pub fn build_proof(left: u64, right: u64, selector: bool) -> Result<Vec<u8>, JsValue> {
        set_panic_hook();

        let (circuits, instances): (Vec<_>, Vec<_>) = iter::once(())
            .map(|()| {
                let a = Fp::from(left);
                let b = Fp::from(right);
                let s = Fp::from(selector);

                let result = match selector {
                    true => right,
                    false => left
                };

                (
                    MuxCircuit::<Fp> {
                        a: Some(a), 
                        b: Some(b), 
                        selector: Some(s)
                    },
                    Instance {
                        result
                    },
                )
            })
            .unzip();

        let pk = ProvingKey::build();
        let proof = Proof::create_raw(&pk, &circuits, &instances).unwrap();
        Ok(proof)
    }

    #[wasm_bindgen]
    pub fn verify_proof(raw_proof: &[u8], raw_public_inputs: &[u8]) -> 
    Result<bool, JsValue> {
        set_panic_hook();
        let public_inputs = raw_public_inputs.to_vec();
        let instances: Vec<_> = public_inputs.iter()
        .map(|pi| {
            Instance {
                result: *pi as u64
            }
        }).collect();

        let vk = VerifyingKey::build();
        let proof = Proof::new(raw_proof.to_vec());
        match proof.verify(&vk, &instances) {
            Ok(_) => (),
            Err(_) => return Err("Proof is not valid!".into()),
        }

        Ok(true)
    }
    
}