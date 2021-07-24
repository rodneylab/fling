extern crate openssl;
use openssl::{
    rsa::{Padding, Rsa},
    symm::Cipher,
};
use std::str;

pub fn main() {
    let passphrase = "my_passphrase";
    let (public_key_pem, private_key_pem) = generate_rsa_public_key_pair(&passphrase[..]);
    let ciphertext = rsa_public_key_encrypt(public_key_pem);
    let plaintext =
        rsa_public_key_decrypt(ciphertext, private_key_pem, &passphrase[..]);
    println!("Plaintext: {:?}", String::from(str::from_utf8(&plaintext).unwrap()));
}

pub fn generate_rsa_public_key_pair(passphrase: &str) -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(4096).unwrap();
    let private_key: Vec<u8> = rsa
        // .private_key_to_pem_passphrase(Cipher::aes_256_gcm(), passphrase.as_bytes())
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), passphrase.as_bytes())
        .unwrap();
    let public_key: Vec<u8> = rsa.public_key_to_pem().unwrap();
    (public_key, private_key)
}

pub fn rsa_public_key_decrypt(
    ciphertext: Vec<u8>,
    private_key_pem: Vec<u8>,
    passphrase: &str,
) -> Vec<u8> {
    let rsa;
    match Rsa::private_key_from_pem_passphrase(private_key_pem.as_slice(), passphrase.as_bytes()) {
        Ok(value) => rsa = value,
        Err(_error) => panic!("Check private key password"),
    }
    let mut plaintext: Vec<u8> = vec![0; rsa.size() as usize];
    match rsa.private_decrypt(&ciphertext, &mut plaintext, Padding::PKCS1) {
        Ok(_) => println!("Public key decryption complete"),
        Err(_error) => panic!("Error in public key decryption"),
    }
    plaintext
}

pub fn rsa_public_key_encrypt(public_key_pem: Vec<u8>) -> Vec<u8> {
    let message = "message";
    let rsa;
    match Rsa::public_key_from_pem(public_key_pem.as_slice()) {
        Ok(value) => rsa = value,
        Err(error) => panic!("{:?}", error),
    }
    let mut ciphertext: Vec<u8> = vec![0; rsa.size() as usize];
    match rsa.public_encrypt(message.as_bytes(), &mut ciphertext, Padding::PKCS1) {
        Ok(_) => println!("Public key encrytion complete"),
        Err(_error) => panic!("Error in public key encryption"),
    }
    let ciphertext: Vec<u8> = ciphertext;
    ciphertext
}
