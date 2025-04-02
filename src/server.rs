use crate::handshake;
use crate::serialization;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub async fn start_server(
    secret: EphemeralSecret,
    public_key: PublicKey,
) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[SERVER] Listening on 127.0.0.1:8080");
    let (mut socket, _) = listener.accept().await?;
    println!("[SERVER] Client connected");

    let mut peer_bytes = [0u8; 32];
    socket.read_exact(&mut peer_bytes).await?;

    socket.write_all(public_key.as_bytes()).await?;

    let shared_secret = handshake::start_handshake(secret, PublicKey::from(peer_bytes));
    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    loop {
        match serialization::deserialize_message(&mut socket, &cipher).await {
            Ok(plaintext) => {
                println!(
                    "[SERVER] Decrypted message: {}",
                    String::from_utf8_lossy(&plaintext)
                );
            }
            Err(e) => {
                eprintln!("[SERVER] Error decoding message: {:?}", e);
                Err(e)?;
            }
        }
    }
}
