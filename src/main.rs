#![feature(const_generics)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

use fasthash::xx;
use bytevec::ByteEncodable;


struct BloomFilter {
    bins: Vec<bool>,
    bin_count: u32,
    seeds: Vec<u32>,
}

impl BloomFilter {

    fn insert(&mut self, element: u64) {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            self.bins[(xx::hash32_with_seed(&element_bytes, *seed) % self.bin_count) as usize] = true;
        }
    }

    fn contains(&self, element: u64) -> bool {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            if !self.bins[(xx::hash32_with_seed(&element_bytes, *seed) % self.bin_count) as usize] {
                return false;
            }
        }

        return true;
    }

}

fn main() {
    println!("Hello, world!");
    let mut rng = OsRng;

    let generator = RISTRETTO_BASEPOINT_POINT;

    let partial_key_1 = Scalar::random(&mut rng);
    let blinded_key_1 = &partial_key_1 * &generator;
    let partial_key_2 = Scalar::random(&mut rng);
    let blinded_key_2 = &partial_key_2 * &generator;
    let partial_key_3 = Scalar::random(&mut rng);
    let blinded_key_3 = &partial_key_3 * &generator;

    let public_key = &blinded_key_1 + &blinded_key_2 + &blinded_key_3;

    let message = RistrettoPoint::random(&mut rng);

    let randomness = Scalar::random(&mut rng);
    let ciphertext_1 = &randomness * &generator;
    let ciphertext_2 = &message + (&randomness * &public_key);

    let share_1 = &ciphertext_1 * &partial_key_1;
    let share_2 = &ciphertext_1 * &partial_key_2;
    let share_3 = &ciphertext_1 * &partial_key_3;

    let decryption = &ciphertext_2 - (&share_1 + &share_2 + &share_3);

    println!("{}", message == decryption);

    let mut bloom_filter = BloomFilter { bins: vec![false; 10], bin_count: 10, seeds: vec![3, 5] };
    bloom_filter.insert(4);

    println!("{}", &bloom_filter.contains(6));
    println!("{}", &bloom_filter.contains(3));
    println!("{}", &bloom_filter.contains(4));
}
