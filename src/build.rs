use halo2::{
    pasta::Fp,
    dev::MockProver
};

use crate::{
    circuit::MuxCircuit,
    keys::{ProvingKey, VerifyingKey, K}
};

use pasta_curves::{
    vesta
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
    circuit: MuxCircuit<Fp>,
}


#[wasm_bindgen]
impl MuxWasm {
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
}