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

#[magnus::wrap(class = "RbMumbleProtocol::CryptState")]
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

    pub fn decrypt(&self, encrypted: Vec<u8>) -> Result<Vec<u8>, Error> {
        match self.0.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                buffer.extend_from_slice(&encrypted);

                match state.decrypt(&mut buffer) {
                    Ok(_) => Ok(buffer.to_vec()),
                    Err(crypt_state::DecryptError::Repeat) => {
                        Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "DecryptError::Repeat"))
                    },
                    Err(crypt_state::DecryptError::Late) => {
                        Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "DecryptError::Late"))
                    },
                    Err(crypt_state::DecryptError::Mac) => {
                        Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "DecryptError::Mac"))
                    },
                    Err(crypt_state::DecryptError::Eof) => {
                        Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "DecryptError::Eof"))
                    }
                }
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
