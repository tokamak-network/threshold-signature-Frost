use clap::Parser;
use helper::{RosterPublicKey, RosterSigningKey};
use rand::RngCore;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Number of keys to generate
    count: usize,
}

fn main() {
    let args = Args::parse();
    let mut rng = rand::thread_rng();

    for _ in 0..args.count {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);

        // Use helper's RosterSigningKey to ensure compatibility
        let sk = RosterSigningKey::EdwardsOnBls12381(sk_bytes);
        let pk = sk.public_key();

        let pk_hex = match pk {
            RosterPublicKey::EdwardsOnBls12381(h) => h,
            _ => panic!("Expected EdwardsOnBls12381 key"),
        };

        println!("{} {}", hex::encode(sk_bytes), pk_hex);
    }
}
