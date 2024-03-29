use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;

use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;

use bytevec::ByteEncodable;
use curve25519_dalek::traits::IsIdentity;
use permutation_iterator::Permutor;
use rand::RngCore;
use sets_multisets::sets::{bloom_filter_indices, gen_sets_with_union, Set};
use std::ops::Add;
use xxh3::hash64_with_seed;

use structopt::StructOpt;

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

#[derive(Copy, Clone)]
struct Ciphertext {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl Add for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext {
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}

define_add_variants!(LHS = Ciphertext, RHS = Ciphertext, Output = Ciphertext);

struct Party<'a> {
    generator: RistrettoPoint,
    rng: OsRng,
    set: &'a Set,
    partial_key: Option<Scalar>,
    blinded_key: Option<RistrettoPoint>,
    bloom_filter: Option<Vec<bool>>,
    alphas: Option<Vec<RistrettoPoint>>,
    betas: Option<Vec<RistrettoPoint>>,
}

impl<'a> Party<'a> {
    fn create(rng: OsRng, set: &'a Set) -> Self {
        Party {
            generator: RISTRETTO_BASEPOINT_POINT,
            rng,
            set,
            partial_key: None,
            blinded_key: None,
            bloom_filter: None,
            alphas: None,
            betas: None,
        }
    }

    fn generate_keys(&mut self) {
        self.partial_key = Some(Scalar::random(&mut self.rng));
        self.blinded_key = Some(self.partial_key.unwrap() * self.generator)
    }

    fn build_bloom_filter(&mut self, m_bins: usize, h_hashes: usize) {
        self.bloom_filter = Some(self.set.to_bloom_filter(m_bins, h_hashes))
    }

    fn build_selective_bloom_filter(&mut self, m_bins: usize, h_hashes: usize, mask: u64) {
        let mut bloom_filter = vec![false; m_bins];

        for element in &self.set.elements {
            // Only instert the element if the masked bits of this hash (with a constant seed) are all 0
            let element_bytes = (*element as u64).encode::<u64>().unwrap();
            if (hash64_with_seed(&element_bytes, 1337) & mask) != 0 {
                continue;
            }

            for index in bloom_filter_indices(element, m_bins, h_hashes) {
                bloom_filter[index] = true;
            }
        }

        self.bloom_filter = Some(bloom_filter);
    }

    fn build_ciphertexts(&mut self) {
        self.alphas = Some(vec![]);
        self.betas = Some(vec![]);
        for bin in self.bloom_filter.as_ref().unwrap() {
            if *bin {
                self.alphas
                    .as_mut()
                    .unwrap()
                    .push(RistrettoPoint::random(&mut self.rng));
                self.betas
                    .as_mut()
                    .unwrap()
                    .push(RistrettoPoint::random(&mut self.rng));
            } else {
                //let (alpha, beta) = self.public_key.as_ref().unwrap().encrypt_identity(&mut self.rng);
                let randomness = Scalar::random(&mut self.rng);
                self.alphas
                    .as_mut()
                    .unwrap()
                    .push(randomness * RISTRETTO_BASEPOINT_POINT);
                self.betas
                    .as_mut()
                    .unwrap()
                    .push(randomness * self.blinded_key.unwrap());
            }
        }
    }

    fn shuffle_decrypt(
        &mut self,
        alphas: &[Vec<RistrettoPoint>],
        betas: &[RistrettoPoint],
        public_keys: &Vec<RistrettoPoint>,
    ) -> (Vec<Vec<RistrettoPoint>>, Vec<RistrettoPoint>) {
        let permutation_key: u64 = self.rng.next_u64();
        let permutor = Permutor::new_with_u64_key(
            self.bloom_filter.as_ref().unwrap().len() as u64,
            permutation_key,
        );

        let mut shuffled_alphas: Vec<Vec<RistrettoPoint>> = vec![];
        let mut shuffled_betas: Vec<RistrettoPoint> = vec![];
        for permuted in permutor {
            let current_alphas = &alphas[permuted as usize];

            let mut new_alphas = vec![];
            let mut new_beta = betas[permuted as usize]
                - self.partial_key.unwrap() * current_alphas.last().unwrap();

            for (alpha, public_key) in current_alphas[..current_alphas.len() - 1]
                .iter()
                .zip(public_keys)
            {
                let randomness = Scalar::random(&mut self.rng);

                new_alphas.push(alpha + randomness * RISTRETTO_BASEPOINT_POINT);
                new_beta += randomness * public_key;
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
    #[structopt(short = "n", long)]
    party_count: usize,
    #[structopt(short = "k", long)]
    set_size: usize,
    #[structopt(short = "d", long)]
    domain_size: usize,
    #[structopt(short = "m", long)]
    max_bins: usize,
    #[structopt(short = "c", long)]
    cardinality: usize,
    #[structopt(short = "M", long, default_value = "0")]
    selective_insertion_mask: u64,
}

fn main() {
    let opt: Opt = Opt::from_args();
    println!("{:#?}", opt);

    println!("Hello, world!");
    let rng = OsRng;

    //let sets: Vec<HashSet<u64>> = (0..opt.party_count).map(|_| HashSet::from_iter((0..opt.set_size).map(|_| rng.gen_range(0, &opt.domain_size)))).collect();
    //let sets = generate_sets(rng, opt.party_count, opt.set_size, opt.domain_size, opt.cardinality);
    let sets = gen_sets_with_union(
        opt.party_count,
        opt.set_size,
        opt.domain_size,
        opt.cardinality,
    );

    let now = Instant::now();
    let mut parties: Vec<Party> = sets.iter().map(|set| Party::create(rng, set)).collect();

    println!("Setup complete");

    //let (hash_count_h, max_standard_deviation) = compute_filter_params(&opt.max_bins as &u64, opt.set_size, (opt.party_count * opt.set_size) as u64);
    let hash_count_h = 1;
    println!("Hash count: {}", hash_count_h);

    // Let parties generate their keys
    for party in parties.iter_mut() {
        party.generate_keys();
    }

    // Let parties generate the public key
    let blinded_keys: Vec<RistrettoPoint> = parties
        .iter()
        .map(|party| party.blinded_key.unwrap())
        .collect();
    // for party in parties.iter_mut() {
    //     party.generate_public_key(&blinded_keys);
    // }
    println!("{}", now.elapsed().as_millis());

    let now = Instant::now();
    // Let parties build their Bloom filters
    for party in parties.iter_mut() {
        if opt.selective_insertion_mask == 0 {
            party.build_bloom_filter(opt.max_bins, hash_count_h);
        } else {
            party.build_selective_bloom_filter(
                opt.max_bins,
                hash_count_h,
                opt.selective_insertion_mask,
            )
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
    let mut alphas: Vec<Vec<RistrettoPoint>> = (0..opt.max_bins)
        .map(|j| {
            parties
                .iter()
                .map(|p| p.alphas.as_ref().unwrap()[j as usize])
                .collect::<Vec<RistrettoPoint>>()
        })
        .collect();

    let mut betas: Vec<RistrettoPoint> = parties[0].betas.as_ref().unwrap().to_vec();
    for party in parties.iter().take(opt.party_count as usize).skip(1) {
        betas = betas
            .iter()
            .zip(party.betas.as_ref().unwrap().iter())
            .map(|(a, b)| a + b)
            .collect();
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
        println!(
            "Estimated set union cardinality: {}",
            -(opt.max_bins as f64) * (1f64 - total as f64 / opt.max_bins as f64).ln()
                / hash_count_h as f64
        );
    } else {
        println!(
            "DEBUG: {}",
            (1f64
                - total as f64
                    / (opt.max_bins as f64
                        / (1 << opt.selective_insertion_mask.count_ones()) as f64))
        );
        println!(
            "Estimated set union cardinality (DROPOUT): {}",
            -(opt.max_bins as f64)
                * (1 << opt.selective_insertion_mask.count_ones()) as f64
                * (1f64 - total as f64 / opt.max_bins as f64).ln()
                / hash_count_h as f64
        );
    }

    let union = Set::union(&sets);
    println!("Actual set union cardinality: {}", union.len())
}

// cargo run --release -- --cardinality 3000 --domain-size 100000 --max-bins 10000 --party-count 5 --set-size 1000
