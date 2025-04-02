use aes::cipher::consts::U12;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce};
use std::error::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub fn serialize_message(cipher: &Aes256Gcm, nonce: &Nonce<U12>, plaintext: &[u8]) -> Vec<u8> {
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failure!");

    let mut message = Vec::with_capacity(12 + 2 + ciphertext.len());
    message.extend_from_slice(nonce.as_slice());
    message.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    message.extend_from_slice(&ciphertext);
    message
}

pub async fn deserialize_message(
    socket: &mut TcpStream,
    cipher: &Aes256Gcm,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut nonce_bytes = [0u8; 12];
    socket.read_exact(&mut nonce_bytes).await?;

    let mut len_bytes = [0u8; 2];
    socket.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    let mut ciphertext = vec![0u8; len];
    socket.read_exact(&mut ciphertext).await?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    Ok(plaintext)
}
