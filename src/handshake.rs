use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub fn generate_secret() -> EphemeralSecret {
    EphemeralSecret::random_from_rng(OsRng)
}

pub fn generate_public_key(secret: &EphemeralSecret) -> PublicKey {
    PublicKey::from(secret)
}

pub fn start_handshake(sk: EphemeralSecret, pk: PublicKey) -> SharedSecret {
    let shared = sk.diffie_hellman(&pk);
    println!("Key exchange done: {:x?}", shared.as_bytes());
    shared
}
