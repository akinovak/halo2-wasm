use halo2::{
    pasta::Fp,
    dev::MockProver
};

use crate::{
    circuit::MuxCircuit,
    keys::{ProvingKey, VerifyingKey}
};

use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// pub fn set_panic_hook() {
//     console_error_panic_hook::set_once();
// }

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
    pub fn new() -> MuxWasm {
        MuxWasm {
            circuit: MuxCircuit::<Fp> {
                a: Some(Fp::one()), 
                b: Some(Fp::one()), 
                selector: Some(Fp::zero())
            },
        }
    }

    #[wasm_bindgen]
    pub fn proof() {
        let k = 4;
    
        let a = Fp::from(3);
        let b = Fp::from(2);
        let selector = Fp::from(0);
    
        let circuit = MuxCircuit {
            a: Some(a),
            b: Some(b),
            selector: Some(selector)
        };

        let mut public_inputs = vec![];

        if selector == Fp::one() {
            public_inputs.push(b)
        } else {
            public_inputs.push(a)
        }

        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        let verification_result = prover.verify();
        if verification_result == Ok(()) {
            alert("Woorks file");
        }
    }


}