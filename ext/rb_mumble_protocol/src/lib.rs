use std::cell::RefCell;

use magnus::{class, define_module, method, function, prelude::*, Error, RHash};

use bytes::BytesMut;

pub mod crypt_state;

#[magnus::wrap(class = "RbMumbleProtocol::CryptState", free_immediatly, size)]
struct CryptStateRef(RefCell<crypt_state::CryptState>);

impl CryptStateRef {
    pub fn new() -> Self {
        Self(RefCell::new(crypt_state::CryptState::generate_new()))
    }

    pub fn new_from(
        key: Vec<u8>,
        encrypt_nonce: Vec<u8>,
        decrypt_nonce: Vec<u8>,
    ) -> Self {
        let new_key =
            key
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Key of length {} but it was {}", 16, v.len()));

        let new_encrypt_nonce =
            encrypt_nonce
            .try_into()
            .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Encrypt nonce of length {} but it was {}", 16, v.len()));

        let new_decrypt_nonce =
            decrypt_nonce
                .try_into()
                .unwrap_or_else(|v: Vec<u8>| panic!("Expected a Decrypt nonce of length {} but it was {}", 16, v.len()));

        let new_state = crypt_state::CryptState::new_from(
            new_key,
            new_encrypt_nonce,
            new_decrypt_nonce
        );

        Self(RefCell::new(new_state))
    }

    pub fn key(&self) -> Vec<u8> { self.0.try_borrow_mut().unwrap().get_key().to_vec() }
    pub fn encrypt_nonce(&self) -> Vec<u8> { self.0.try_borrow_mut().unwrap().get_encrypt_nonce().to_vec() }
    pub fn decrypt_nonce(&self) -> Vec<u8> { self.0.try_borrow_mut().unwrap().get_decrypt_nonce().to_vec() }

    pub fn stats(&self) -> RHash {
        let hash = RHash::new();
        let state = self.0.try_borrow_mut().unwrap();

        let _ = hash.aset("good", state.get_good());
        let _ = hash.aset("late", state.get_late());
        let _ = hash.aset("lost", state.get_lost());

        hash
    }

    pub fn encrypt(&self, src: Vec<u8>) -> Vec<u8> {
        let mut buffer = BytesMut::new();

        self.0.try_borrow_mut().unwrap().encrypt(src, &mut buffer);

        buffer.to_vec()
    }

    pub fn decrypt(&self, encrypted: Vec<u8>) -> Vec<u8> {
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&encrypted);

        self.0.try_borrow_mut().unwrap().decrypt(&mut buffer).unwrap();

        buffer.to_vec()
    }
}

#[magnus::init]
fn init() -> Result<(), Error> {
    let module = define_module("RbMumbleProtocol")?;
    let class = module.define_class("CryptState", class::object())?;

    class.define_singleton_method("new", function!(CryptStateRef::new, 0))?;
    class.define_singleton_method("new_from", function!(CryptStateRef::new_from, 3))?;

    class.define_method("key", method!(CryptStateRef::key, 0))?;
    class.define_method("encrypt_nonce", method!(CryptStateRef::encrypt_nonce, 0))?;
    class.define_method("decrypt_nonce", method!(CryptStateRef::decrypt_nonce, 0))?;
    class.define_method("stats", method!(CryptStateRef::stats, 0))?;

    class.define_method("encrypt", method!(CryptStateRef::encrypt, 1))?;
    class.define_method("decrypt", method!(CryptStateRef::decrypt, 1))?;

    Ok(())
}

#[test]
fn encrypt_and_decrypt_are_inverse() {
    let server_state = CryptStateRef::new();
    // swap nonce vectors side to side
    let client_state = CryptStateRef::new_from(
        server_state.key(),
        server_state.decrypt_nonce(),
        server_state.encrypt_nonce()
    );

    let src= "test".as_bytes().to_vec();
    let encrypted= server_state.encrypt(src.clone());
    let result= client_state.decrypt(encrypted.clone());

    assert_eq!(src, result);
}
