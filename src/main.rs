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

use std::iter::FromIterator;

use structopt::StructOpt;
use std::collections::HashSet;

use std::time::Instant;

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

    fn encrypt_identity(&self, rng: &mut OsRng) -> (RistrettoPoint, RistrettoPoint) {
        let randomness = Scalar::random(rng);
        return (&randomness * &RISTRETTO_BASEPOINT_POINT, &randomness * &self.point);
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
    alphas: Option<Vec<RistrettoPoint>>,
    betas: Option<Vec<RistrettoPoint>>
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
            alphas: None,
            betas: None,
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

    fn build_selective_bloom_filter(&mut self, m_bins: &u64, h_hashes: &u64, mask: &u32) {
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
            let element_bytes = element.encode::<u64>().unwrap();
            if (xx::hash32_with_seed(element_bytes, 1337) & mask) == 0 {
                // Only insert the element if the masked bits are all 0
                self.bloom_filter.as_mut().unwrap().insert(element);
            }
        }
    }

    fn build_ciphertexts(&mut self) {
        self.alphas = Some(vec![]);
        self.betas = Some(vec![]);
        for bin in &self.bloom_filter.as_ref().unwrap().bins {
            if *bin {
                self.alphas.as_mut().unwrap().push(RistrettoPoint::random(&mut self.rng));
                self.betas.as_mut().unwrap().push(RistrettoPoint::random(&mut self.rng));
            } else {
                //let (alpha, beta) = self.public_key.as_ref().unwrap().encrypt_identity(&mut self.rng);
                let randomness = Scalar::random(&mut self.rng);
                self.alphas.as_mut().unwrap().push(&randomness * &RISTRETTO_BASEPOINT_POINT);
                self.betas.as_mut().unwrap().push(&randomness * &self.blinded_key.unwrap());
            }
        }
    }

    fn shuffle_decrypt(&mut self, alphas: &Vec<Vec<RistrettoPoint>>, betas: &Vec<RistrettoPoint>, public_keys: &Vec<RistrettoPoint>)
        -> (Vec<Vec<RistrettoPoint>>, Vec<RistrettoPoint>) {
        let permutation_key: u64 = self.rng.next_u64();
        let permutor = Permutor::new_with_u64_key(self.bloom_filter.as_ref().unwrap().bin_count as u64, permutation_key);

        let mut shuffled_alphas: Vec<Vec<RistrettoPoint>> = vec![];
        let mut shuffled_betas: Vec<RistrettoPoint> = vec![];
        for permuted in permutor {
            let current_alphas = &alphas[permuted as usize];

            let mut new_alphas = vec![];
            let mut new_beta = betas[permuted as usize] - self.partial_key.unwrap() * current_alphas.last().unwrap();

            for (alpha, public_key) in current_alphas[..current_alphas.len()-1].iter().zip(public_keys) {
                let randomness = Scalar::random(&mut self.rng);

                new_alphas.push(alpha + &randomness * &RISTRETTO_BASEPOINT_POINT);
                new_beta += &randomness * public_key;
            }

            shuffled_alphas.push(new_alphas);
            shuffled_betas.push(new_beta);
        }

        (shuffled_alphas, shuffled_betas)
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
    #[structopt(short="m", long)]
    max_bins: u64,
    #[structopt(short="c", long)]
    cardinality: u64,
    #[structopt(short="M", long, default_value="0")]
    selective_insertion_mask: u32,
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

fn generate_sets(mut rng: OsRng, set_count: u64, set_size: u64, domain_size: u64, union_cardinality: u64) -> Vec<HashSet<u64>> {
    // TODO: Make sure union is has union_cardinality length
    let union: Vec<u64> = (0..union_cardinality).map(|_| rng.gen_range(0, &domain_size)).collect();
    let mut sets: Vec<HashSet<u64>> = vec![HashSet::from_iter(vec![]); set_count as usize];
    //for i in 0..(set_count * set_size) {
    //    sets[(i % set_size) as usize].insert()
    //}
    for (index, element) in union.iter().enumerate() {
        sets[index % set_count as usize].insert(element.clone());
    };
    for i in 0..set_count {
        while sets[i as usize].len() < set_size as usize {
            sets[i as usize].insert(union[rng.gen_range(0, union_cardinality) as usize]);
        }
    }

    return sets;

    //let intersection_size = (set_count * set_size - union_cardinality) / set_count;
    //let intersection: HashSet<u64> = (0..opt.set_size).map(|_| rng.gen_range(0, &opt.domain_size)).collect();
    //let remaining_elements: HashSet<u64> =
}

fn main() {
    let opt: Opt = Opt::from_args();
    println!("{:#?}", opt);

    println!("Hello, world!");
    let mut rng = OsRng;

    //let sets: Vec<HashSet<u64>> = (0..opt.party_count).map(|_| HashSet::from_iter((0..opt.set_size).map(|_| rng.gen_range(0, &opt.domain_size)))).collect();
    let sets = generate_sets(rng, opt.party_count, opt.set_size, opt.domain_size, opt.cardinality);

    let now = Instant::now();
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
    // for party in parties.iter_mut() {
    //     party.generate_public_key(&blinded_keys);
    // }
    println!("{}", now.elapsed().as_millis());

    let now = Instant::now();
    // Let parties build their Bloom filters
    for party in parties.iter_mut() {
        if opt.selective_insertion_mask == 0 {
            party.build_bloom_filter(&opt.max_bins, &hash_count_h);
        } else {
            party.build_selective_bloom_filter(&opt.max_bins, &hash_count_h, &opt.selective_insertion_mask)
        }
    }

    println!("Encrypt");

    // Let parties build their ciphertexts
    for party in parties.iter_mut() {
        party.build_ciphertexts();
    }
    println!("{}", now.elapsed().as_millis());

    println!("Aggregate");
    let now = Instant::now();
    // Aggregate the ciphertexts and initialize the accumulators
    let mut alphas: Vec<Vec<RistrettoPoint>> = (0..opt.max_bins).map(|j| parties.iter().map(|p| p.alphas.as_ref().unwrap()[j as usize]).collect::<Vec<RistrettoPoint>>()).collect();

    let mut betas: Vec<RistrettoPoint> = parties[0].betas.as_ref().unwrap().iter().copied().collect();
    for i in 1..(opt.party_count as usize) {
        betas = betas.iter().zip(parties[i].betas.as_ref().unwrap().iter()).map(|(a, b)| a + b).collect();
    }
    println!("{}", now.elapsed().as_millis());

    println!("Shuffle-decrypt");
    let now = Instant::now();
    // Perform shuffle-decrypt protocol
    for party in parties[1..].iter_mut().rev() {
        println!("Party");
        (alphas, betas) = party.shuffle_decrypt(&alphas, &betas, &blinded_keys);
    }

    println!("Decrypt");

    // Perform the final combination step to decrypt
    let mut decryptions: Vec<RistrettoPoint> = vec![];
    for j in 0..(opt.max_bins as usize) {
        decryptions.push(betas[j] - parties[0].partial_key.unwrap() * alphas[j].first().unwrap());
    }

    // println!("Decrypts");
    // for decryption in decryptions {
    //     println!("{}", !decryption.is_identity());
    // }

    let total: u64 = decryptions.iter().map(|d| !d.is_identity() as u64).sum();
    println!("{}", now.elapsed().as_millis());
    println!("Total: {}", total);

    if opt.selective_insertion_mask == 0 {
        println!("Estimated set union cardinality: {}", -(opt.max_bins as f64) * (1f64 - total as f64 / opt.max_bins as f64).ln() / hash_count_h as f64);
    } else {
        println!("DEBUG: {}", (1f64 - total as f64 / (opt.max_bins as f64 / (1 << opt.selective_insertion_mask.count_ones()) as f64)));
        println!("Estimated set union cardinality (DROPOUT): {}", -(opt.max_bins as f64) * (1 << opt.selective_insertion_mask.count_ones()) as f64 * (1f64 - total as f64 / opt.max_bins as f64).ln() / hash_count_h as f64);
    }

    let mut union: HashSet<u64> = HashSet::from_iter(vec![]);
    for set in sets {
        union = union.union(&set).cloned().collect();
    }
    println!("Actual set union cardinality: {}", union.len())
}
