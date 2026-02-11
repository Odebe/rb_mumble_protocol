use std::cell::RefCell;

use magnus::{
    method, prelude::*,
    Error, RHash,
    RClass, RModule, Ruby, Value,
    value::{Lazy},
    exception::ExceptionClass,
    gc::register_mark_object,
    scan_args::{get_kwargs, scan_args},
    typed_data
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

#[magnus::wrap(class = "RbMumbleProtocol::CryptState", name = "Rust CryptState wrapper", free_immediately, size)]
#[derive(Default)]
struct CryptStateRef {
  state: RefCell<crypt_state::CryptState>
}

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
    fn initialize(
      ruby: &Ruby,
      rb_self: typed_data::Obj<Self>,
      args: &[Value],
    ) -> Result<(), Error> {
      let args = scan_args::<(), (), (), (), _, ()>(args)?;
      let kwargs = get_kwargs::<_, (), (Option<[u8; 16]>, Option<[u8; 16]>, Option<[u8; 16]>), ()>(
          args.keywords,
          &[],
          &["key", "encrypt_nonce", "decrypt_nonce"],
      )?;

      *rb_self.state.borrow_mut() = match kwargs.optional {
          (Some(key), Some(enc), Some(dec)) => crypt_state::CryptState::new_from(key, enc, dec),
          (None, None, None) => crypt_state::CryptState::generate_new(),
          _ => {
              return Err(Error::new(
                  ruby.exception_arg_error(),
                  "Expected none kwargs, or all of: key, encrypt_nonce and decrypt_nonce",
              ))
          }
      };

      Ok(())
    }

    pub fn set_decrypt_nonce(&self, nonce: Vec<u8>) -> Result<(), Error> {
        match self.state.try_borrow_mut() {
            Ok(mut ref_) => {
                match &nonce.clone().try_into() {
                    Ok(array) => Ok(ref_.set_decrypt_nonce(array)),
                    Err(_e) => {
                        let msg = format!("Expected a Decrypt nonce of length {}", 16);
                        let err = Error::new(get_ruby().get_inner(&BASE_ERROR), msg);

                        Err(err)
                    }
                }
            },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn key(&self) -> Result<Vec<u8>, Error> {
        match self.state.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_key().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn encrypt_nonce(&self) -> Result<Vec<u8>, Error> {
        match self.state.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_encrypt_nonce().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt_nonce(&self) -> Result<Vec<u8>, Error> {
        match self.state.try_borrow() {
            Ok(ref_) => { Ok(ref_.get_decrypt_nonce().to_vec()) },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn stats(&self) -> Result<RHash, Error> {
        match self.state.try_borrow() {
            Ok(state) => {
                let hash = Ruby::hash_new(&get_ruby());

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
        match self.state.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                state.encrypt(src, &mut buffer);

                Ok(buffer.to_vec())
            },
            Err(_e) => { Err(Error::new(get_ruby().get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt(&self, encrypted: Vec<u8>) -> Result<DecryptResult, Error> {
        match self.state.try_borrow_mut() {
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
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.class_object().const_get::<_, RModule>("RbMumbleProtocol").unwrap();
    let class1 = module.const_get::<_, RClass>("CryptState").unwrap();

    class1.define_alloc_func::<CryptStateRef>();
    class1.define_method("initialize", method!(CryptStateRef::initialize, -1))?;

    class1.define_method("key", method!(CryptStateRef::key, 0))?;
    class1.define_method("encrypt_nonce", method!(CryptStateRef::encrypt_nonce, 0))?;
    class1.define_method("decrypt_nonce", method!(CryptStateRef::decrypt_nonce, 0))?;
    class1.define_method("stats", method!(CryptStateRef::stats, 0))?;
    class1.define_method("set_decrypt_nonce", method!(CryptStateRef::set_decrypt_nonce, 1))?;

    class1.define_method("encrypt", method!(CryptStateRef::encrypt, 1))?;
    class1.define_method("decrypt", method!(CryptStateRef::decrypt, 1))?;

    let class2 = module.const_get::<_, RClass>("DecryptResult").unwrap();
    class2.define_method("success?", method!(DecryptResult::is_success, 0))?;
    class2.define_method("data", method!(DecryptResult::data, 0))?;
    class2.define_method("reason_raw_value", method!(DecryptResult::reason_raw_value, 0))?;

    Ok(())
}
