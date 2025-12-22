use libcrux_ml_tkem::{mlkem768, tkem768, ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE};
use rand::{rngs::OsRng, TryRngCore};

fn main() {
    let mut randomness = [0u8; KEY_GENERATION_SEED_SIZE];
    OsRng.try_fill_bytes(&mut randomness).unwrap();

    let key_pair = mlkem768::generate_key_pair(randomness);

    let mut randomness = [0u8; ENCAPS_SEED_SIZE];
    
    OsRng.try_fill_bytes(&mut randomness).unwrap();
    let test_tag_1 = b"This is a test tag for TKEM.";
    let (ct,ss) = tkem768::encapsulate_with_tag(key_pair.public_key(), randomness,test_tag_1);
    println!("Ciphertext (ct): {}", hex::encode(ct.as_slice())); // 假设 ct 有 as_slice() 方法
    println!("Shared Secret (ss): {}", hex::encode(ss.as_slice())); // 假设 ss 有 as_slice() 方法
    let ss = tkem768::decapsulate_with_tag(key_pair.private_key(), &ct,test_tag_1);
    println!("dss:{}",hex::encode(ss.as_slice()));
    
}