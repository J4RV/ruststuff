extern crate crossbeam;
extern crate crypto;

use std::time::Instant;

use crypto::mac::Mac;

use self::crypto::hmac::Hmac;
use self::crypto::sha1::Sha1;

fn main() {
    let mac = hex::decode("f3c2ae334dc98a387601c85ef83c77360943023a").unwrap();

    let thread_res = crossbeam::scope(|s| {
        let msg = "341567891 487654 500".as_bytes();
        let mac = &mac;
        let digest = Sha1::new();
        let now = Instant::now();
        for cpu in 0..num_cpus::get() {
            s.spawn(move |_| {
                for i in ((cpu as u8)..=255).step_by(num_cpus::get()) {
                    if let Some(valid_key) = bruteforce_block(i, msg, mac, &digest) {
                        println!("Done in {} seconds", now.elapsed().as_secs());
                        println!("Key: {:x?} for msg '{}' and mac '{}'", valid_key, std::str::from_utf8(msg).unwrap(), hex::encode(mac));
                        std::process::exit(0);
                    }
                }
            });
        }
    });

    if let Err(e) = thread_res {
        println!("Error in thread result: {:x?}", e);
        std::process::exit(2);
    }

    // All threads joined. None found the key.
    println!("Valid key not found!");
    std::process::exit(1);
}

fn bruteforce_block(i: u8, msg: &[u8], mac: &[u8], digest: &Sha1) -> Option<[u8; 4]> {
    let mut key = [i, 0, 0, 0];
    for x in 0..=255 {
        for y in 0..=255 {
            for z in 0..=255 {
                if valid_mac(msg, mac, &key, digest) {
                    return Some(key);
                }
                key[3] = z
            }
            key[2] = y
        }
        key[1] = x
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
