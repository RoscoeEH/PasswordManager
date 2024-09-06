mod server;
mod client;

use std::env;

fn main() {
    letargs: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: cargo run [server|client]");
        return;
    }

    match args[1].as_str() {
        "server" => server::run(),
        "client" => client::run(),
        _ => eprintln!("Invalid argument. Use 'server' or 'client'."),
    }
}
