use std::cell::RefCell;

use magnus::{
    method, prelude::*,
    Error, RHash, RString,
    RClass, RModule, Ruby, Value,
    Symbol,
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

#[magnus::wrap(class = "RbMumbleProtocol::CryptState", name = "Rust CryptState wrapper", free_immediately, size)]
#[derive(Default)]
struct CryptStateRef {
  state: RefCell<crypt_state::CryptState>
}

impl CryptStateRef {
    fn initialize(
      ruby: &Ruby,
      rb_self: typed_data::Obj<Self>,
      args: &[Value],
    ) -> Result<(), Error> {
      let args = scan_args::<(), (), (), (), _, ()>(args)?;
      let kwargs = get_kwargs::<_, (), (Option<RString>, Option<RString>, Option<RString>), ()>(
          args.keywords,
          &[],
          &["key", "encrypt_nonce", "decrypt_nonce"],
      )?;

      *rb_self.state.borrow_mut() = match kwargs.optional {
          (Some(key), Some(enc), Some(dec)) => {
            crypt_state::CryptState::new_from(
              rstring_to_array::<{crypt_state::KEY_SIZE}>(ruby, &key)?,
              rstring_to_array::<{crypt_state::BLOCK_SIZE}>(ruby, &enc)?,
              rstring_to_array::<{crypt_state::BLOCK_SIZE}>(ruby, &dec)?,
            )
          },
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

    pub fn set_decrypt_nonce(ruby: &Ruby, rb_self: &Self, nonce: RString) -> Result<(), Error> {
        match rb_self.state.try_borrow_mut() {
            Ok(mut ref_) => {
                match rstring_to_array::<{crypt_state::BLOCK_SIZE}>(ruby, &nonce) {
                    Ok(array) => Ok(ref_.set_decrypt_nonce(&array)),
                    Err(_e) => {
                        let msg = format!("Expected a Decrypt nonce of length {}", 16);
                        let err = Error::new(ruby.get_inner(&BASE_ERROR), msg);

                        Err(err)
                    }
                }
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn key(ruby: &Ruby, rb_self: &Self) -> Result<RString, Error> {
        match rb_self.state.try_borrow() {
            Ok(ref_) => {
              let key = ref_.get_key();
              let ruby_string = ruby.str_from_slice(key);

              Ok(ruby_string)
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn encrypt_nonce(ruby: &Ruby, rb_self: &Self) -> Result<RString, Error> {
        match rb_self.state.try_borrow() {
            Ok(ref_) => {
              let nonce = ref_.get_encrypt_nonce();
              let ruby_string = ruby.str_from_slice(&nonce);

              Ok(ruby_string)
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt_nonce(ruby: &Ruby, rb_self: &Self) -> Result<RString, Error> {
        match rb_self.state.try_borrow() {
            Ok(ref_) => {
              let nonce = ref_.get_decrypt_nonce();
              let ruby_string = ruby.str_from_slice(&nonce);

              Ok(ruby_string)
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn stats(ruby: &Ruby, rb_self: &Self) -> Result<RHash, Error> {
        match rb_self.state.try_borrow() {
            Ok(state) => {
                let hash = Ruby::hash_new(ruby);

                let _ = hash.aset(Ruby::to_symbol(ruby, "good"), state.get_good());
                let _ = hash.aset(Ruby::to_symbol(ruby, "late"), state.get_late());
                let _ = hash.aset(Ruby::to_symbol(ruby, "lost"), state.get_lost());

                Ok(hash)
            },
            Err(_e) => {
                Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error"))
            }
        }
    }

    pub fn encrypt(ruby: &Ruby, rb_self: &Self, src: RString) -> Result<RString, Error> {
        match rb_self.state.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                let src_slice = unsafe { src.as_slice() };

                state.encrypt(src_slice, &mut buffer);

                Ok(ruby.str_from_slice(&buffer))
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }

    pub fn decrypt(ruby: &Ruby, rb_self: &Self, encrypted: RString) -> Result<(RString, Symbol), Error> {
        match rb_self.state.try_borrow_mut() {
            Ok(mut state) => {
                let mut buffer = BytesMut::new();
                let src_slice = unsafe { encrypted.as_slice() };

                buffer.extend_from_slice(&src_slice);
                let result = state.decrypt(&mut buffer);

                let ruby_string = ruby.str_from_slice(&buffer);
                let reason =
                    match result {
                        Ok(()) => Ruby::to_symbol(ruby, "ok"),
                        Err(e) => match e {
                            DecryptError::Repeat => Ruby::to_symbol(ruby, "repeat"),
                            DecryptError::Late   => Ruby::to_symbol(ruby, "late"),
                            DecryptError::Mac    => Ruby::to_symbol(ruby, "bad_mac"),
                            DecryptError::Eof    => Ruby::to_symbol(ruby, "eof"),
                        }
                    };

                Ok((ruby_string, reason))
            },
            Err(_e) => { Err(Error::new(ruby.get_inner(&BASE_ERROR), "borrow error")) }
        }
    }
}

fn rstring_to_array<const N: usize>(ruby: &Ruby, rstring: &RString) -> Result<[u8; N], Error> {
  let slice = unsafe { rstring.as_slice() };
  slice.try_into().map_err(|_| Error::new(ruby.get_inner(&BASE_ERROR), format!("Expected {N} bytes")))
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

    Ok(())
}
