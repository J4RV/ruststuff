extern crate crypto;

use self::crypto::sha1::Sha1;
use self::crypto::hmac::Hmac;
use crypto::mac::Mac;
use std::time::{Instant, Duration};
use std::thread;

fn main() {
    let digest = Sha1::new();
    let msg = b"341567891 487654 500";
    let mac = hex::decode("f3c2ae334dc98a387601c85ef83c77360943023a").unwrap();

    let now = Instant::now();
    for cpu in 0..num_cpus::get() {
        let mac = mac.clone();
        thread::spawn(move || {
            let mac = mac.as_slice();
            for i in ((cpu as u8)..=255).step_by(num_cpus::get()) {
                if let Some(valid_key) = bruteforce_block(i, msg, mac, &digest) {
                    println!("Key: {:x?}", valid_key);
                    println!("Done in {} seconds", now.elapsed().as_secs());
                    std::process::exit(0);
                }
            }
        });
    }

    thread::sleep(Duration::from_secs(60 * 30));
    println!("Key not found in 30 minutes");
}

fn bruteforce_block(i: u8, msg: &[u8], mac: &[u8], digest: &Sha1) -> Option<[u8; 4]> {
    for x in 0..=255 {
        for y in 0..=255 {
            for z in 0..=255 {
                if valid_mac(msg, mac, &[i, x, y, z], &digest) {
                    return Some([i, x, y, z]);
                }
            }
        }
    }
    return None;
}

fn valid_mac(msg: &[u8], mac: &[u8], key: &[u8], digest: &Sha1) -> bool {
    let mut hasher = Hmac::new(*digest, key);

    hasher.input(msg);
    let result = hasher.result();
    let res = result.code();

    res == mac
}
