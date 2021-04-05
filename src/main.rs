use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;
use curve25519_dalek::ristretto::RistrettoPoint;

use fasthash::xx;
use bytevec::ByteEncodable;
use std::ops::Add;
use permutation_iterator::Permutor;
use curve25519_dalek::traits::IsIdentity;

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

    let public_key = PublicKey::create(vec![blinded_key_1, blinded_key_2, blinded_key_3]);

    let mut bloom_filter_1 = BloomFilter { bins: vec![false; 10], bin_count: 10, seeds: vec![3, 5] };
    bloom_filter_1.insert(4);

    println!("{}", &bloom_filter_1.contains(6));
    println!("{}", &bloom_filter_1.contains(3));
    println!("{}", &bloom_filter_1.contains(4));

    let mut bloom_filter_2 = BloomFilter { bins: vec![false; 10], bin_count: 10, seeds: vec![3, 5] };
    bloom_filter_2.insert(2);
    bloom_filter_2.insert(3);
    bloom_filter_2.insert(4);

    let mut bloom_filter_3 = BloomFilter { bins: vec![false; 10], bin_count: 10, seeds: vec![3, 5] };
    bloom_filter_3.insert(1);
    bloom_filter_3.insert(3);

    let mut ciphertexts_1: Vec<Ciphertext> = vec![];
    for bin in &bloom_filter_1.bins {
        if *bin {
            ciphertexts_1.push(Ciphertext {
                c1: RistrettoPoint::random(&mut rng),
                c2: RistrettoPoint::random(&mut rng) });
        } else {
            ciphertexts_1.push(public_key.encrypt_identity(&mut rng));
        }
    }
    let mut ciphertexts_2: Vec<Ciphertext> = vec![];
    for bin in &bloom_filter_2.bins {
        if *bin {
            ciphertexts_2.push(Ciphertext {
                c1: RistrettoPoint::random(&mut rng),
                c2: RistrettoPoint::random(&mut rng) });
        } else {
            ciphertexts_2.push(public_key.encrypt_identity(&mut rng));
        }
    }
    let mut ciphertexts_3: Vec<Ciphertext> = vec![];
    for bin in &bloom_filter_3.bins {
        if *bin {
            ciphertexts_3.push(Ciphertext {
                c1: RistrettoPoint::random(&mut rng),
                c2: RistrettoPoint::random(&mut rng) });
        } else {
            ciphertexts_3.push(public_key.encrypt_identity(&mut rng));
        }
    }

    let mut aggregated_ciphertexts: Vec<Ciphertext> = vec![];
    for i in 0..10 {
        aggregated_ciphertexts.push(&ciphertexts_1[i] + &ciphertexts_2[i] + &ciphertexts_3[i]);
    }

    let permutation_key_1: [u8; 32] = [0xBA; 32];
    let permutor_1 = Permutor::new_with_slice_key(10, permutation_key_1);
    let permutation_key_2: [u8; 32] = [0x12; 32];
    let permutor_2 = Permutor::new_with_slice_key(10, permutation_key_2);
    let permutation_key_3: [u8; 32] = [0x33; 32];
    let permutor_3 = Permutor::new_with_slice_key(10, permutation_key_3);

    let mut accumulators: Vec<RistrettoPoint> = vec![];

    let mut shuffled_ciphertexts_1: Vec<&Ciphertext> = vec![];
    for permuted in permutor_1 {
        shuffled_ciphertexts_1.push(&aggregated_ciphertexts[permuted as usize]);
    }
    for ciphertext in &shuffled_ciphertexts_1 {
        accumulators.push(ciphertext.c1 * &partial_key_1);
    }

    let mut shuffled_accumulators_2: Vec<RistrettoPoint> = vec![];
    let mut shuffled_ciphertexts_2: Vec<&Ciphertext> = vec![];
    for permuted in permutor_2 {
        shuffled_accumulators_2.push(accumulators[permuted as usize]);
        shuffled_ciphertexts_2.push(shuffled_ciphertexts_1[permuted as usize]);
    }
    for i in 0..10 {
        shuffled_accumulators_2[i] += shuffled_ciphertexts_2[i].c1 * &partial_key_2;
    }
    let mut shuffled_accumulators_3: Vec<RistrettoPoint> = vec![];
    let mut shuffled_ciphertexts_3: Vec<&Ciphertext> = vec![];
    for permuted in permutor_3 {
        shuffled_accumulators_3.push(shuffled_accumulators_2[permuted as usize]);
        shuffled_ciphertexts_3.push(shuffled_ciphertexts_2[permuted as usize]);
    }
    for i in 0..10 {
        shuffled_accumulators_3[i] += shuffled_ciphertexts_3[i].c1 * &partial_key_3;
    }

    let mut decryptions: Vec<RistrettoPoint> = vec![];
    for i in 0..10 {
        decryptions.push(shuffled_ciphertexts_3[i].c2 - shuffled_accumulators_3[i]);
    }

    println!("Decrypts");
    for decryption in decryptions {
        println!("{}", !decryption.is_identity());
    }

    println!("BF1");
    for bin in &bloom_filter_1.bins {
        println!("{}", bin);
    }
    println!("BF2");
    for bin in &bloom_filter_2.bins {
        println!("{}", bin);
    }
    println!("BF3");
    for bin in &bloom_filter_3.bins {
        println!("{}", bin);
    }

    // let share_1 = &ciphertext_1 * &partial_key_1;
    // let share_2 = &ciphertext_1 * &partial_key_2;
    // let share_3 = &ciphertext_1 * &partial_key_3;
    //
    // let decryption = &ciphertext_2 - (&share_1 + &share_2 + &share_3);
    //
    // println!("{}", message == decryption);


}
