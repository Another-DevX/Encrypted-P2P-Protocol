mod client;
mod handshake;
mod serialization;
mod server;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run [server|client]");
        return;
    }

    let secret = handshake::generate_secret();
    let public_key = handshake::generate_public_key(&secret);

    if args[1] == "server" {
        if let Err(e) = server::start_server(secret, public_key).await {
            eprintln!("Error on server: {}", e);
        }
    } else {
        if let Err(e) = client::start_client(secret, public_key).await {
            eprintln!("Error on client: {}", e);
        }
    }
}
