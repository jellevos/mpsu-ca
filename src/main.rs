#![feature(destructuring_assignment)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

use fasthash::xx;
use bytevec::ByteEncodable;
use std::ops::Add;
use permutation_iterator::{Permutor};
use curve25519_dalek::traits::{IsIdentity, Identity};
use rand::RngCore;

macro_rules! define_add_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }
    };
}


struct BloomFilter {
    bins: Vec<bool>,
    bin_count: u32,
    seeds: Vec<u32>,
}

impl BloomFilter {

    fn insert(&mut self, element: &u64) {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            self.bins[(xx::hash32_with_seed(&element_bytes, *seed) % self.bin_count) as usize] = true;
        }
    }

    fn contains(&self, element: &u64) -> bool {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            if !self.bins[(xx::hash32_with_seed(&element_bytes, *seed) % self.bin_count) as usize] {
                return false;
            }
        }

        return true;
    }

}

#[derive(Copy, Clone)]
struct Ciphertext {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl Add for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext {
            c1: &self.c1 + &rhs.c1,
            c2: &self.c2 + &rhs.c2,
        }
    }
}

define_add_variants!(LHS = Ciphertext, RHS = Ciphertext, Output = Ciphertext);

struct PublicKey {
    point: RistrettoPoint,
}

impl PublicKey {

    fn create(blinded_keys: Vec<RistrettoPoint>) -> Self {
        let mut point = blinded_keys[0];

        for i in 1..blinded_keys.len() {
            point += blinded_keys[i];
        };

        PublicKey {point}
    }

    fn encrypt(&self, rng: &mut OsRng, message: &RistrettoPoint) -> Ciphertext {
        let randomness = Scalar::random(rng);
        Ciphertext {
            c1: &randomness * &RISTRETTO_BASEPOINT_POINT,
            c2: message + (&randomness * &self.point),
        }
    }

    fn encrypt_identity(&self, rng: &mut OsRng) -> Ciphertext {
        let randomness = Scalar::random(rng);
        Ciphertext {
            c1: &randomness * &RISTRETTO_BASEPOINT_POINT,
            c2: &randomness * &self.point,
        }
    }

}

struct Party {
    generator: RistrettoPoint,
    rng: OsRng,
    set: Vec<u64>,
    partial_key: Option<Scalar>,
    blinded_key: Option<RistrettoPoint>,
    public_key: Option<PublicKey>,
    bloom_filter: Option<BloomFilter>,
    ciphertexts: Option<Vec<Ciphertext>>,
}

impl Party {
    fn create(rng: OsRng, set: Vec<u64>) -> Self {
        Party {
            generator: RISTRETTO_BASEPOINT_POINT,
            rng,
            set,
            partial_key: None,
            blinded_key: None,
            public_key: None,
            bloom_filter: None,
            ciphertexts: None,
        }
    }

    fn generate_keys(&mut self) {
        self.partial_key = Some(Scalar::random(&mut self.rng));
        self.blinded_key = Some(&self.partial_key.unwrap() * &self.generator)
    }

    fn generate_public_key(&mut self, blinded_keys: Vec<RistrettoPoint>) {
        self.public_key = Some(PublicKey::create(blinded_keys));
    }

    fn build_bloom_filter(&mut self, m_bins: usize, h_hashes: u32) {
        let mut seeds: Vec<u32> = vec![];
        for i in 0..h_hashes {
            seeds.push(i);
        }

        self.bloom_filter = Some(BloomFilter {
            bins: vec![false; m_bins],
            bin_count: m_bins as u32,
            seeds,
        });

        for element in &self.set {
            self.bloom_filter.as_mut().unwrap().insert(element);
        }
    }

    fn build_ciphertexts(&mut self) {
        self.ciphertexts = Some(vec![]);
        for bin in &self.bloom_filter.as_ref().unwrap().bins {
            if *bin {
                self.ciphertexts.as_mut().unwrap().push(Ciphertext {
                    c1: RistrettoPoint::random(&mut self.rng),
                    c2: RistrettoPoint::random(&mut self.rng) });
            } else {
                self.ciphertexts.as_mut().unwrap().push(self.public_key.as_ref().unwrap().encrypt_identity(&mut self.rng));
            }
        }
    }

    fn shuffle_decrypt(mut self, ciphertexts: &Vec<Ciphertext>, accumulators: &Vec<RistrettoPoint>)
        -> (Vec<Ciphertext>, Vec<RistrettoPoint>) {
        let permutation_key: u64 = self.rng.next_u64();
        let permutor = Permutor::new_with_u64_key(self.bloom_filter.unwrap().bin_count as u64, permutation_key);

        let mut shuffled_accumulators: Vec<RistrettoPoint> = vec![];
        let mut shuffled_ciphertexts: Vec<Ciphertext> = vec![];
        for permuted in permutor {
            shuffled_accumulators.push(accumulators[permuted as usize]);
            shuffled_ciphertexts.push(ciphertexts[permuted as usize]);
        }

        for i in 0..10 {
            shuffled_accumulators[i] += shuffled_ciphertexts[i].c1 * &self.partial_key.unwrap();
        }

        (shuffled_ciphertexts, shuffled_accumulators)
    }
}

fn main() {
    println!("Hello, world!");
    let mut rng = OsRng;

    let mut party_1 = Party::create(rng, vec![6, 3, 4]);
    let mut party_2 = Party::create(rng, vec![2, 3, 4]);
    let mut party_3 = Party::create(rng, vec![1, 3]);

    party_1.generate_keys();
    party_2.generate_keys();
    party_3.generate_keys();

    party_1.generate_public_key(vec![party_1.blinded_key.unwrap(), party_2.blinded_key.unwrap(), party_3.blinded_key.unwrap()]);
    party_2.generate_public_key(vec![party_1.blinded_key.unwrap(), party_2.blinded_key.unwrap(), party_3.blinded_key.unwrap()]);
    party_3.generate_public_key(vec![party_1.blinded_key.unwrap(), party_2.blinded_key.unwrap(), party_3.blinded_key.unwrap()]);

    party_1.build_bloom_filter(10, 2);
    party_2.build_bloom_filter(10, 2);
    party_3.build_bloom_filter(10, 2);

    party_1.build_ciphertexts();
    party_2.build_ciphertexts();
    party_3.build_ciphertexts();

    let mut ciphertexts: Vec<Ciphertext> = vec![];
    for i in 0..10 {
        ciphertexts.push(&party_1.ciphertexts.as_ref().unwrap()[i] + &party_2.ciphertexts.as_ref().unwrap()[i] + &party_3.ciphertexts.as_ref().unwrap()[i]);
    }
    let mut accumulators: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); 10];

    (ciphertexts, accumulators) = party_1.shuffle_decrypt(&ciphertexts, &accumulators);
    (ciphertexts, accumulators) = party_2.shuffle_decrypt(&ciphertexts, &accumulators);
    (ciphertexts, accumulators) = party_3.shuffle_decrypt(&ciphertexts, &accumulators);

    let mut decryptions: Vec<RistrettoPoint> = vec![];
    for i in 0..10 {
        decryptions.push(ciphertexts[i].c2 - accumulators[i]);
    }

    println!("Decrypts");
    for decryption in decryptions {
        println!("{}", !decryption.is_identity());
    }

    // println!("BF1");
    // for bin in &bloom_filter_1.bins {
    //     println!("{}", bin);
    // }
    // println!("BF2");
    // for bin in &bloom_filter_2.bins {
    //     println!("{}", bin);
    // }
    // println!("BF3");
    // for bin in &bloom_filter_3.bins {
    //     println!("{}", bin);
    // }
}
