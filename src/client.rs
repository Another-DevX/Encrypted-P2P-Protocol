use crate::handshake;
use crate::serialization;
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub async fn start_client(
    secret: EphemeralSecret,
    public_key: PublicKey,
) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("[CLIENT] Connected to server");

    stream.write_all(public_key.as_bytes()).await?;

    let mut peer_bytes = [0u8; 32];
    stream.read_exact(&mut peer_bytes).await?;

    let shared_secret = handshake::start_handshake(secret, PublicKey::from(peer_bytes));
    let key = GenericArray::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let mut interval = time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;

        let plaintext = b"LMAO this is an encripted message";
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let serialized_message = serialization::serialize_message(&cipher, &nonce, plaintext);

        stream.write_all(&serialized_message).await?;
        println!("[CLIENT] Sent encripted message");
    }
}
