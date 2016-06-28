#![feature(test)]

extern crate test;
extern crate ascon;

use test::Bencher;
use ascon::aead_encrypt;


#[bench]
fn ascon_encrypt_bench(b: &mut Bencher) {
    let key = [0; 16];
    let iv = [0; 16];
    let aad = [0; 16];
    let message = [0; 1024];

    b.bytes = message.len() as u64;
    b.iter(|| aead_encrypt(&key, &iv, &message, &aad));
}
