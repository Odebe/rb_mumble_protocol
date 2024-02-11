use std::cell::RefCell;

use magnus::{
    class, define_module,
    method, function, prelude::*,
    Error, RHash, RModule, Ruby,
    value::{Lazy},
    exception::ExceptionClass,
    gc::register_mark_object,
};

use bytes::BytesMut;

static BASE_ERROR: Lazy<ExceptionClass> = Lazy::new(|ruby| {
    let ex = ruby
        .class_object()
        .const_get::<_, RModule>("RbMumbleProtocol")
        .unwrap()
        .const_get("Error")
        .unwrap();

    // ensure `ex` is never garbage collected (e.g. if constant is
    // redefined) and also not moved under compacting GC.
    register_mark_object(ex);
    ex
});

pub mod crypt_state;

use crypt_state::{DecryptError};

impl Into<u8> for DecryptError {
    fn into(self: DecryptError) -> u8 {
        match self {
            DecryptError::Repeat => 1,
            DecryptError::Late => 2,
            DecryptError::Mac => 3,
            DecryptError::Eof => 4
        }
    }
}

#[magnus::wrap(class = "RbMumbleProtocol::CryptState", size)]
struct CryptStateRef(RefCell<crypt_state::CryptState>);

#[magnus::wrap(class = "RbMumbleProtocol::DecryptResult", free_immediately, size)]
struct DecryptResult {
    buffer: RefCell<Vec<u8>>,
    reason_raw: u8
}

impl DecryptResult {
    pub fn new(buffer: Vec<u8>, result: Result<(), DecryptError>) -> Self {
        let reason_raw =
            match result {
                Ok(()) => 0,
                Err(e) => e.into()
            };

        Self {
            buffer: RefCell::new(buffer),
            reason_raw: reason_raw.into()
        }
    }

    pub fn is_success(&self) -> bool {
        self.reason_raw == 0
    }

    pub fn data(&self) -> Vec<u8> {
        self.buffer.borrow().to_vec()
    }

    pub fn reason_raw_value(&self) -> u8 {
        self.reason_raw
    }
}

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

    pub fn key(&self) -> Result<Vec<u8>, Error> {
        match self.0.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_key().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn encrypt_nonce(&self) -> Result<Vec<u8>, Error> {
        match self.0.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_encrypt_nonce().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt_nonce(&self) -> Result<Vec<u8>, Error> {
        match self.0.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_decrypt_nonce().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn stats(&self) -> Result<RHash, Error> {
        match self.0.try_borrow() {
            Ok(state) => {
                let hash = RHash::new();

                let _ = hash.aset("good", state.get_good());
                let _ = hash.aset("late", state.get_late());
                let _ = hash.aset("lost", state.get_lost());

                Ok(hash)
            },
            Err(_e) => {
                Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error"))
            }
        }
    }

    pub fn encrypt(&self, src: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.0.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                state.encrypt(src, &mut buffer);

                Ok(buffer.to_vec())
            },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt(&self, encrypted: Vec<u8>) -> Result<DecryptResult, Error> {
        match self.0.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                buffer.extend_from_slice(&encrypted);
                let result = state.decrypt(&mut buffer);

                Ok(DecryptResult::new(buffer.to_vec(), result))
            },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }
}

#[inline]
fn get_ruby() -> Ruby {
    unsafe { Ruby::get_unchecked() }
}

#[magnus::init]
fn init() -> Result<(), Error> {
    let module = define_module("RbMumbleProtocol")?;
    let class1 = module.define_class("CryptState", class::object())?;

    class1.define_singleton_method("new", function!(CryptStateRef::new, 0))?;
    class1.define_singleton_method("new_from", function!(CryptStateRef::new_from, 3))?;

    class1.define_method("key", method!(CryptStateRef::key, 0))?;
    class1.define_method("encrypt_nonce", method!(CryptStateRef::encrypt_nonce, 0))?;
    class1.define_method("decrypt_nonce", method!(CryptStateRef::decrypt_nonce, 0))?;
    class1.define_method("stats", method!(CryptStateRef::stats, 0))?;

    class1.define_method("encrypt", method!(CryptStateRef::encrypt, 1))?;
    class1.define_method("decrypt", method!(CryptStateRef::decrypt, 1))?;

    let class2 = module.define_class("DecryptResult", class::object())?;
    class2.define_method("success?", method!(DecryptResult::is_success, 0))?;
    class2.define_method("data", method!(DecryptResult::data, 0))?;
    class2.define_method("reason_raw_value", method!(DecryptResult::reason_raw_value, 0))?;

    Ok(())
}
