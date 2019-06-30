extern crate crypto;

use self::crypto::sha1::Sha1;
use self::crypto::hmac::Hmac;
//use self::crypto::digest::Digest;
use crypto::mac::Mac;
use std::time::Instant;

fn main() {
    let digest = Sha1::new();
    let key = &[0x21, 0xAE, 0x26, 0xAC];
    let msg = b"341567891 487654 500";
    let mac = hex::decode("f3c2ae334dc98a387601c85ef83c77360943023a").unwrap();
    let mac = mac.as_slice();

    let now = Instant::now();
    for x in 0..=255{
        for y in 0..=255 {
            println!("{:x?}", &[x,y,0,0]);
            for z in 0..=255 {
                for w in 0..=255 {
                    if valid_mac(msg, mac, &[x,y,z,w], digest){
                        println!("Valid mac! {:x?}", key);
                        println!("Done in {} seconds", now.elapsed().as_secs());
                        return;
                    }
                }
            }
        }
    }
}

fn valid_mac(msg:&[u8], mac:&[u8], key: &[u8], digest: Sha1) -> bool {
    let mut hasher = Hmac::new(digest, key);

    hasher.input(msg);
    let result = hasher.result();
    let res = result.code();

    res == mac
}
