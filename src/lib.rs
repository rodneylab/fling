extern crate ring;
use ring::rand::SecureRandom;
use std::str;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

/* encryption steps
 * user and recipient need already to have a public key pair
 * 1. generate a one time password
 * 2. encrypt the message with the one time password
 * 3. encrypt the one time password with the private key
 * 4. upload the encrypted file and encrypted password
 *
 * functions needed:
 *   - public key pair generation
 *   - aead encryption
 *   - aead decryption
 *   - random password generation
 *   - public key encrypt
 *   - public key decrypt
 *
 */

// #[wasm_bindgen]
// pub fn decrypt_message() {
//     let content = b"encrypted message".to_vec();
//     let nonce = vec![0; 12];

//     let password = b"password";
//     let additional_authenticated_data = Aad::from(vec![1, 2, 3]);

//     let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

//     let mut key = [0; 32];
//     derive(
//         PBKDF2_HMAC_SHA256,
//         NonZeroU32::new(100_000).unwrap(),
//         &salt,
//         &password[..],
//         &mut key,
//     );

//     let mut in_out = content.clone();

//     alert(&format!("Tag len {}", &AES_256_GCM.tag_len()));
//     for _ in 0..AES_256_GCM.tag_len() {
//         in_out.push(0);
//     }

//     let key = UnboundKey::new(&AES_256_GCM, &key).unwrap();

//     let nonce_sequence = OneNonceSequence::new(Nonce::try_assume_unique_for_key(&nonce).unwrap());

//     let mut opening_key: OpeningKey<OneNonceSequence> =
//         BoundKey::<OneNonceSequence>::new(key, nonce_sequence);

//     let decrypted_data = opening_key
//         .open_in_place(additional_authenticated_data, &mut in_out)
//         .unwrap();

//     alert(&format!(
//         "{:?}",
//         String::from_utf8(decrypted_data.to_vec()).unwrap()
//     ));
// }

// #[wasm_bindgen]
// pub fn encrypt_message() {
//     // need 96 bit nonce
//     // nonce: 5bf11a0951f0bfc7ea5c9e58
//     // key: 73ad7bbbbc640c845a150f67d058b279849370cd2c1f3c67c4dd6c869213e13a
//     let password = b"password";

//     let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

//     let mut key = [0; 32];
//     derive(
//         PBKDF2_HMAC_SHA256,
//         NonZeroU32::new(100_000).unwrap(),
//         &salt,
//         &password[..],
//         &mut key,
//     );

//     let content = b"plaintext message".to_vec();
//     alert(&format!("Content to encrypt length {}", content.len()));
//     let additional_authenticated_data = Aad::from(vec![1, 2, 3]);

//     let mut in_out = content.clone();

//     alert(&format!("Tag len {}", &AES_256_GCM.tag_len()));
//     for _ in 0..AES_256_GCM.tag_len() {
//         in_out.push(0);
//     }

//     let mut nonce = vec![0; 12];
//     let rand = SystemRandom::new();
//     rand.fill(&mut nonce).unwrap();

//     let key = UnboundKey::new(&AES_256_GCM, &key).unwrap();
//     let nonce_sequence = OneNonceSequence::new(Nonce::try_assume_unique_for_key(&nonce).unwrap());
//     let mut sealing_key: SealingKey<OneNonceSequence> =
//         BoundKey::<OneNonceSequence>::new(key, nonce_sequence);

//     let output_size = sealing_key
//         .seal_in_place_append_tag(additional_authenticated_data, &mut in_out)
//         .unwrap();
//     alert(&format!("Encrypted data's size {:?}", output_size));
// }

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

// pub fn generate_ed25519_public_key_pair() {
//     let rng = ring::rand::SystemRandom::new();
//     let pkcs8_bytes;
//     match ring::signature::Ed25519KeyPair::generate_pkcs8(&rng) {
//         Ok(value) => pkcs8_bytes = value,
//         Err(error) => std::panic::panic_any(error),
//     }
//         alert(&format!("{:?}", pkcs8_bytes.as_ref()));
// }

// pub fn generate_ecdsa_public_key_pair() {
//     let rng = SystemRandom::new();
//     let pkcs8_bytes;
//     match EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING,&rng) {
//         Ok(value) => pkcs8_bytes = value,
//         Err(error) => std::panic::panic_any(error),
//     }
//         alert(&format!("{:?}", pkcs8_bytes.as_ref()));
// }

// pub fn public_key_encrypt_sign_ecdsa() {
//         let key_pair;
//     match signature::EcdsaKeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
//         Ok(value) => key_pair = value,
//         Err(error) => std::panic::panic_any(error),
//     }
//     const MESSAGE: &[u8] = b"hello, world";

//     let sig = key_pair.sign(MESSAGE);

// }

#[wasm_bindgen]
pub fn generate_one_time_password() {
    let rng = ring::rand::SystemRandom::new();
    let mut result_buffer = vec![0; 180];
    match rng.fill(&mut result_buffer) {
        Ok(_value) => alert(&format!("{:?}", result_buffer)),
        Err(error) => alert(&format!("{:?}", error)),
    }
    alert("generated");
}
//     let key_pair;
//     match signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
//         Ok(value) => key_pair = value,
//         Err(error) => std::panic::panic_any(error),
//     }
//     const MESSAGE: &[u8] = b"hello, world";

//     let sig = key_pair.sign(MESSAGE);

//     let peer_public_key_bytes = key_pair.public_key().as_ref();

//     let peer_public_key =
//         signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
//     alert(&format!("{:?}", str::from_utf8(peer_public_key_bytes)));
//     let result;
//     match peer_public_key.verify(MESSAGE, sig.as_ref()) {
//         Ok(value) => result = value,
//         Err(error) => std::panic::panic_any(error),
//     }
//     alert(&format!("{:?}", result));
//     alert("Hello");
// }

// struct OneNonceSequence(Option<Nonce>);

// impl OneNonceSequence {
//     fn new(nonce: Nonce) -> Self {
//         Self(Some(nonce))
//     }
// }

// impl NonceSequence for OneNonceSequence {
//     fn advance(&mut self) -> Result<Nonce, error::Unspecified> {
//         self.0.take().ok_or(error::Unspecified)
//     }
// }
