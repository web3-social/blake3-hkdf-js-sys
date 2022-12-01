mod utils;

use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use hkdf::SimpleHkdf;
use blake3::Hasher;
use js_sys::Error;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Blake3 {
    hasher: Hasher,
}

#[wasm_bindgen]
impl Blake3 {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Blake3 {
        Blake3 {
            hasher: Hasher::new()
        }
    }

    pub fn new_keyed(key: Vec<u8>) -> Result<Blake3, Error> {
        let key: [u8; 32] = key.try_into().map_err(|_| Error::new("invalid key length"))?;
        Ok(
            Blake3 {
                hasher: Hasher::new_keyed(&key)
            }
        )
    }

    pub fn new_derive_key(context: &str) -> Blake3 {
        Blake3 {
            hasher: Hasher::new_derive_key(context)
        }
    }

    pub fn update(&mut self, input: Box<[u8]>) {
        self.hasher.update(input.as_ref());
    }

    pub fn finalize(&self) -> Vec<u8> {
        self.hasher.finalize().as_bytes().to_vec()
    }

    pub fn reset(&mut self) {
        self.hasher.reset();
    }
}

#[wasm_bindgen]
pub fn hkdf(length: usize, ikm: Box<[u8]>, salt: Option<Box<[u8]>>, info: Option<Box<[u8]>>) -> Result<Vec<u8>, Error> {
    let hk = SimpleHkdf::<Hasher>::new(salt.as_deref(), ikm.as_ref());
    let mut okm = Vec::with_capacity(length);
    okm.resize(length, 0u8);
    hk.expand(info.as_deref().unwrap_or(b""), okm.as_mut_slice()).map_err(|_| Error::new("invalid length"))?;
    Ok(okm)
}

#[wasm_bindgen]
pub fn extract(ikm: Box<[u8]>, salt: Option<Box<[u8]>>) -> Vec<u8> {
    let (out, _) = SimpleHkdf::<Hasher>::extract(salt.as_deref(), ikm.as_ref());
    out.to_vec()
}

#[wasm_bindgen]
pub fn expand(prk: Box<[u8]>, length: usize, info: Option<Box<[u8]>>) -> Result<Vec<u8>, Error> {
    let hk = SimpleHkdf::<Hasher>::from_prk(prk.as_ref()).map_err(|_| Error::new("invalid prk length"))?;
    let mut okm = Vec::with_capacity(length);
    okm.resize(length, 0u8);
    hk.expand(info.as_deref().unwrap_or(b""), okm.as_mut_slice()).map_err(|_| Error::new("invalid length"))?;
    Ok(okm)
}
