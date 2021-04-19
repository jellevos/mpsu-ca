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
use rand::{RngCore, Rng};

use std::convert::TryInto;
use std::iter::FromIterator;

use structopt::StructOpt;
use std::collections::HashSet;

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
    bin_count: u64,
    seeds: Vec<u64>,
}

impl BloomFilter {

    fn insert(&mut self, element: &u64) {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            self.bins[(xx::hash32_with_seed(&element_bytes, *seed as u32) as u64 % self.bin_count) as usize] = true;
        }
    }

    fn contains(&self, element: &u64) -> bool {
        let element_bytes = element.encode::<u64>().unwrap();

        for seed in &self.seeds {
            if !self.bins[(xx::hash32_with_seed(&element_bytes, *seed as u32) as u64 % self.bin_count) as usize] {
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

    fn create(blinded_keys: &Vec<RistrettoPoint>) -> Self {
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

struct Party<'a> {
    generator: RistrettoPoint,
    rng: OsRng,
    set: &'a HashSet<u64>,
    max_bins: u64,
    partial_key: Option<Scalar>,
    blinded_key: Option<RistrettoPoint>,
    public_key: Option<PublicKey>,
    bloom_filter: Option<BloomFilter>,
    ciphertexts: Option<Vec<Ciphertext>>,
}

impl<'a> Party<'a> {
    fn create(rng: OsRng, set: &'a HashSet<u64>, max_bins: u64) -> Self {
        Party {
            generator: RISTRETTO_BASEPOINT_POINT,
            rng,
            set,
            max_bins,
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

    fn generate_public_key(&mut self, blinded_keys: &Vec<RistrettoPoint>) {
        self.public_key = Some(PublicKey::create(blinded_keys));
    }

    fn build_bloom_filter(&mut self, m_bins: &u64, h_hashes: &u64) {
        let mut seeds: Vec<u64> = vec![];
        for i in 0..*h_hashes {
            seeds.push(i);
        }

        self.bloom_filter = Some(BloomFilter {
            bins: vec![false; *m_bins as usize],
            bin_count: *m_bins,
            seeds,
        });

        for element in self.set {
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

    fn shuffle_decrypt(&mut self, ciphertexts: &Vec<Ciphertext>, accumulators: &Vec<RistrettoPoint>)
        -> (Vec<Ciphertext>, Vec<RistrettoPoint>) {
        let permutation_key: u64 = self.rng.next_u64();
        let permutor = Permutor::new_with_u64_key(self.bloom_filter.as_ref().unwrap().bin_count as u64, permutation_key);

        let mut shuffled_accumulators: Vec<RistrettoPoint> = vec![];
        let mut shuffled_ciphertexts: Vec<Ciphertext> = vec![];
        for permuted in permutor {
            shuffled_accumulators.push(accumulators[permuted as usize]);
            shuffled_ciphertexts.push(ciphertexts[permuted as usize]);
        }

        for i in 0..shuffled_accumulators.len() {
            shuffled_accumulators[i] += shuffled_ciphertexts[i].c1 * &self.partial_key.unwrap();
        }

        (shuffled_ciphertexts, shuffled_accumulators)
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "mpsu-ca")]
struct Opt {
    #[structopt(short="n", long)]
    party_count: u64,
    #[structopt(short="k", long)]
    set_size: u64,
    #[structopt(short="d", long)]
    domain_size: u64,
    //#[structopt(short="s", long)]
    //standard_deviation: u64,
    #[structopt(short="m", long)]
    max_bins: u64,
}

fn prob_0(n_elements: &u64, m_bins: &u64, h_hashes: &u64) -> f64 {
    return (1f64 - (1f64 / *m_bins as f64)).powf((h_hashes * n_elements) as f64);
}

fn partial_binomial(n_elements: &u64, m_bins: &u64, h_hashes: &u64, x_ones: &u64) -> f64 {
    let prob_of_0 = prob_0(n_elements, m_bins, h_hashes);
    return (1f64 - prob_of_0).powf(*x_ones as f64);// * prob_of_0.powf((m_bins - x_ones) as f64);
}

fn compute_filter_params(m_bins: &u64, min_size: u64, max_size: u64) -> (u64, f64) {
    let mut h_hashes = 1u64;
    let mut variance = f64::MAX;

    loop {
        let mut probabilities: Vec<f64> = vec![];

        for n in min_size..=max_size {
            let probability: f64 = partial_binomial(&n, m_bins, &h_hashes, m_bins) /
                (min_size..=max_size).map(|i| partial_binomial(&i, m_bins, &h_hashes, m_bins)).sum::<f64>();
            probabilities.push(probability);
        }

        let mean: f64 = probabilities.iter().enumerate().map(|(x, p)| x as f64 * p).sum();
        let new_variance = probabilities.iter().enumerate().map(|(x, p)| p * (x as f64 - mean) * (x as f64 - mean)).sum();

        println!("{}", new_variance);
        if new_variance > variance {
            return (h_hashes - 1, variance.sqrt());
        }

        variance = new_variance;
        h_hashes += 1;
    }
}

fn main() {
    let opt = Opt::from_args();
    println!("{:#?}", opt);

    println!("Hello, world!");
    let mut rng = OsRng;

    let sets: Vec<HashSet<u64>> = (0..opt.party_count).map(|_| HashSet::from_iter((0..opt.set_size).map(|_| rng.gen_range(0, &opt.domain_size)))).collect();

    let mut parties: Vec<Party> = sets.iter().map(|set| Party::create(rng, set, opt.max_bins)).collect();

    println!("Setup complete");

    //let (hash_count_h, max_standard_deviation) = compute_filter_params(&opt.max_bins as &u64, opt.set_size, (opt.party_count * opt.set_size) as u64);
    let hash_count_h = 1;
    println!("Hash count: {}", hash_count_h);

    // Let parties generate their keys
    for party in parties.iter_mut() {
        party.generate_keys();
    }

    // Let parties generate the public key
    let blinded_keys: Vec<RistrettoPoint> = parties.iter().map(|party| party.blinded_key.unwrap()).collect();
    for party in parties.iter_mut() {
        party.generate_public_key(&blinded_keys);
    }

    // Let parties build their Bloom filters
    for party in parties.iter_mut() {
        party.build_bloom_filter(&opt.max_bins, &hash_count_h);
    }

    println!("Encrypt");

    // Let parties build their ciphertexts
    for party in parties.iter_mut() {
        party.build_ciphertexts();
    }

    println!("Aggregate");

    // Aggregate the ciphertexts and initialize the accumulators
    let mut ciphertexts: Vec<Ciphertext> = parties[0].ciphertexts.as_ref().unwrap().iter().copied().collect();
    for i in 1..(opt.party_count as usize) {
        ciphertexts = ciphertexts.iter().zip(parties[i].ciphertexts.as_ref().unwrap().iter()).map(|(a, b)| a + b).collect();
    }
    let mut accumulators: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); opt.max_bins as usize];

    println!("Shuffle-decrypt");

    // Perform shuffle-decrypt protocol
    for party in parties.iter_mut() {
        println!("Party");
        (ciphertexts, accumulators) = party.shuffle_decrypt(&ciphertexts, &accumulators);
    }

    println!("Decrypt");

    // Perform the final combination step to decrypt
    let mut decryptions: Vec<RistrettoPoint> = vec![];
    for i in 0..(opt.max_bins as usize) {
        decryptions.push(ciphertexts[i].c2 - accumulators[i]);
    }

    // println!("Decrypts");
    // for decryption in decryptions {
    //     println!("{}", !decryption.is_identity());
    // }

    let total: u64 = decryptions.iter().map(|d| !d.is_identity() as u64).sum();
    println!("Total: {}", total);

    println!("Estimated set union cardinality: {}", -(opt.max_bins as f64) * (1f64 - total as f64 / opt.max_bins as f64).ln() / hash_count_h as f64);

    let mut union: HashSet<u64> = HashSet::from_iter(vec![]);
    for set in sets {
        union = union.union(&set).cloned().collect();
    }
    println!("Actual set union cardinality: {}", union.len())
}
