//! # Zero-Knowledge Set Membership Proofs
//!
//! This library implements a zero-knowledge proof system for set membership using polynomial 
//! commitments and KZG (Kate-Zaverucha-Goldberg) proofs. It allows a prover to demonstrate 
//! membership (or non-membership) of an element in a committed set without revealing the 
//! entire set or any additional information.
//!
//! ## Overview
//!
//! The protocol works by:
//! 1. Representing sets as polynomials where roots correspond to set elements
//! 2. Creating polynomial commitments using elliptic curve cryptography
//! 3. Generating zero-knowledge proofs for membership queries
//! 4. Using Schnorr proofs for non-membership cases
//!
//! ## Basic Usage
//!
//! ```rust
//! use kzg::{setup, commitzk, queryzk, verifyzk, Pk};
//! use std::collections::HashSet;
//! use kzg::curve::Curve;
//! use kzg::curve::FastCurve as CurveImpl;
//!
//! // Setup phase
//! let mut randomness = vec![42u128; 10]; // In practice, use cryptographically secure randomness
//! let pk: Pk<CurveImpl> = setup(5, &mut randomness);
//!
//! // Create a set and commit to it
//! let mut set = HashSet::new();
//! set.insert(CurveImpl::scalar_from_literal(&123));
//! set.insert(CurveImpl::scalar_from_literal(&456));
//!
//! let (commitment, phi, phi_hat) = commitzk(&pk, &set, &mut randomness);
//!
//! // Query for membership
//! let query_element = CurveImpl::scalar_from_literal(&123);
//! let (kj, witness, phi_hat_kj, pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, 
//!                                               query_element, &mut randomness);
//!
//! // Verify the proof
//! let is_valid = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
//! assert!(is_valid);
//! ```
//!
//! ## Security Properties
//! 
//! If the provided randomness is suited for cryptographic applications then
//! the following security properties apply
//! 
//! - **Zero-knowledge**: Proofs reveal no information about the set beyond membership
//! - **Soundness**: Invalid proofs are rejected with overwhelming probability
//! - **Completeness**: Valid proofs are always accepted
//!
//! 
//! ### Supported Curve Types
//!
//! The library works with any curve implementing the `Curve` trait, which provides:
//! - **G1 and G2 groups**: Elliptic curve points for commitments and verification
//! - **Scalar field operations**: Arithmetic in the curve's scalar field
//! - **Pairing operations**: Bilinear maps e(G1, G2) → GT for verification
//! - **Hash functions**: Fiat-Shamir transformation for non-interactive proofs
//!
//! ### Example Curve Selection
//!
//! ```
//! // Use a specification-friendly curve (slower but easier to verify)
//! use kzg::curve::Curve;
//! use kzg::{Pk, setup};
//! 
//! let mut randomness = vec![10; 4];
//! let degree = 4;
//! 
//! use kzg::curve::SpecCurve as SpecCurve;
//! let pk: Pk<SpecCurve> = setup(degree, &mut randomness);
//!
//! // Use a performance-optimized curve
//! use kzg::curve::FastCurve as FastCurve;
//! let pk: Pk<FastCurve> = setup(degree, &mut randomness);
//! ```
//!
//! ### Curve Selection Guidelines
//!
//! - **SpecCurve**: Choose for formal verification, auditing, or when simplicity is prioritized
//! - **FastCurve**: Choose for production deployments where performance is critical
//! - **Custom curves**: Implement the `Curve` trait for specialized requirements
//!
//! The same protocol and security guarantees apply regardless of curve choice, allowing
//! users to optimize for their specific deployment constraints.
//!
//! 
//! ## Dependencies
//!
//! This library depends on:
//! - `hacspec_lib` for safe cryptographic primitives
//! - A curve implementation providing elliptic curve operations
//! - `hacspec-bls12-381` for safe elliptic curve operations
//! - `blstrs` for fast elliptic curve operations
//! 
//! ## Generic over curves
//! 
//! Implementing the `Curve` trait allows 

pub mod curve;
use curve::Curve;
use hacspec_lib::*;
use std::collections::HashSet;



/// Public key structure containing the public key parameters
/// 
/// This structure holds the cryptographic parameters generated during the setup phase.
/// It includes powers of a secret value α in both G1 and G2 groups, as well as additional
/// parameters needed for the hiding commitment scheme.
///
/// # Type Parameters
/// 
/// * `T` - The elliptic curve type implementing the `Curve` trait
///
/// # Fields
/// 
/// * `g_powers` - Powers of generator g: [g^(α^d), g^(α^(d-1)), ..., g^α, g]
/// * `h_powers` - Powers of hiding generator h: [h^(α^d), h^(α^(d-1)), ..., h^α, h]  
/// * `h1` - The hiding generator h
/// * `alpha_g2` - g2^α in the G2 group for pairing verification
pub struct Pk<T: Curve> {
    g_powers: Vec<T::G1>,
    h_powers: Vec<T::G1>,
    h1: T::G1,
    alpha_g2: T::G2
}


/// runs the trusted authority setup phase 
///
/// Generates the public parameters needed for the zero-knowledge proof system.
/// This function creates powers of a secret value α that will be used for polynomial
/// commitments. The secret α is derived from the provided randomness and is
/// securely deleted after setup.
///
/// # Arguments
///
/// * `degree` - Maximum degree of polynomials that can be committed to
/// * `random` - Mutable vector of random values used for parameter generation
///
/// # Returns
///
/// A `Pk<T>` structure containing the public parameters
///
/// # Panics
///
/// Panics if random.len() < 2 
///
pub fn setup<T: Curve>(degree: u128, random: &mut Vec<u128>) -> Pk<T> {

    let rand = random.pop().expect("not enough randomness provided");
    let alpha =  T::scalar_from_literal(&rand);

    let mut setup_g1 = Vec::new();
    let mut setup_h1 = Vec::new();
    
    // generate h from some random lambda 
    let rand = random.pop().expect("not enough randomness provided");
    let h = T::g1mul(&T::scalar_from_literal(&rand), &T::g1());

    for i in 0..degree + 1 {
        let power: u128 = (degree - i).into();
        let alpha_power= T::scalar_pow(&alpha, &power);

        setup_g1.push(T::g1mul(&alpha_power, &T::g1()));
        setup_h1.push(T::g1mul(&alpha_power, &h));
    };
    
    let alpha_g2 = T::g2mul(&alpha, &T::g2());

    Pk{g_powers : setup_g1, h_powers : setup_h1, h1 : h, alpha_g2}
}

/// Creates a zero-knowledge commitment to a set
///
/// This function takes a set of elements and creates a polynomial commitment that
/// represents the set. The commitment is unconditionally hiding due to the use of a random polynomial
/// phi_hat(x) that masks the actual set polynomial φ(x).
///
/// # Arguments
///
/// * `pk` - Public parameters from the trusted setup
/// * `set` - The set of elements to commit to
/// * `random` - Mutable vector of random values for the hiding polynomial
///
/// # Returns
///
/// A tuple containing:
/// * `T::G1` - The commitment C = g^φ(α) · h^phi_hat(α)
/// * `Vec<T::Scalar>` - The polynomial φ(x)
/// * `Vec<T::Scalar>` - The hiding polynomial phi_hat(x) 
///
/// # Panics
///
/// Panics if random.len() < set.len()
///
/// # Complexity
///
/// O(n³) where n is the set size, due to polynomial multiplication.
/// Could be optimized using FFT for larger sets.
pub fn commitzk<T: Curve>(pk: &Pk<T>, set: &HashSet<T::Scalar>, random: &mut Vec<u128>) -> (T::G1, Vec<T::Scalar>, Vec<T::Scalar>) {
    let mut phi = vec![T::scalar_from_literal(&1)];
    
    let zero = T::scalar_from_literal(&0);
    
    // Constructing the set is O(n^3) 
    // could be optimized using horner's method
    // or fft. but they are out of scope
    for i in set {
        let mul = vec![T::scalar_from_literal(&1),  zero - *i ];
        phi = multiply::<T>(&phi, &mul);
    }

    let mut phi_hat = vec![T::scalar_from_literal(&0); phi.len()];
    
    // create a random hiding polynomial
    for i in 0..phi_hat.len() {
        let rand = random.pop().expect("not enough randomness provided");
        phi_hat[i] = T::scalar_from_literal(&rand);
    }
    
    let commitment = commit_poly::<T>(&phi, &pk.g_powers, T::g1());
    let hiding_commitment = commit_poly::<T>(&phi_hat, &pk.h_powers, pk.h1);

    
    (T::g1add(&commitment, &hiding_commitment), phi, phi_hat)
}



/// Generates a membership proof for a queried element
///
/// This function creates a zero-knowledge proof that demonstrates whether a queried
/// element is in the committed set. For elements in the set, it reveals the hiding
/// polynomial evaluation. For elements not in the set, it provides a Schnorr proof
/// that the polynomial evaluation is non-zero.
///
/// # Arguments
///
/// * `pk` - Public parameters from the trusted setup
/// * `set` - The original set that was committed to
/// * `phi` - The polynomial φ from `commitzk`
/// * `phi_hat` - The hiding polynomial phi_hat from `commitzk`
/// * `kj` - The element being queried for membership
/// * `random` - Mutable vector of random values for proof generation
///
/// # Returns
///
/// A tuple containing:
/// * `T::Scalar` - The queried element kⱼ
/// * `T::G1` - The witness W = g^ψ(α) · h^psi_hat(α)
/// * `Option<T::Scalar>` - psi_hat(kⱼ) if element is in set, None otherwise
/// * `Option<(T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>` - Schnorr proof if element not in set
///
///
/// # Panics
///
/// Panics if random.len() < 2 
///
pub fn queryzk<T: Curve>(pk: &Pk<T>, set: &HashSet<T::Scalar>, phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, kj: T::Scalar, random: &mut Vec<u128>)
-> (T::Scalar, T::G1, Option<T::Scalar>, Option<(T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>) {

    let (kj, phi_kj, phi_hat_kj, witness) = create_witness(phi, phi_hat, kj, pk);
    
    
    if set.contains(&kj) {
        return (kj, witness, Some(phi_hat_kj), None);
    };
    
    let p1 = T::g1mul(&phi_kj, &T::g1());
    let p2 = T::g1mul(&phi_hat_kj, &pk.h1);
    
    
    let proof = T::g1add(&p1, &p2);

    let (n1, n2, s1, s2) = schnorr_proof(pk, phi_kj, phi_hat_kj, random);

    return (kj, witness, None, Some((proof, n1, n2, s1, s2)));
}


/// Verifies a zero-knowledge membership proof
///
/// This function verifies whether a proof generated by `queryzk` is valid.
/// It handles both membership proofs (where phi_hat(kⱼ) is revealed) and non-membership
/// proofs (where a Schnorr proof is provided).
///
/// # Arguments
///
/// * `pk` - Public parameters from the trusted setup
/// * `commitment` - The commitment from `commitzk`
/// * `pi_sj` - Optional Schnorr proof for non-membership
/// * `kj` - The queried element
/// * `witness` - The witness from `queryzk`
/// * `phi_hat_kj` - Optional evaluation phi_hat(kⱼ) for membership proofs
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise
///
/// # Security
///
/// This function implements the verification equations that ensure:
/// - Membership proofs satisfy: e(W, g2^α - g2^kⱼ) = e(C - h^phi_hat(kⱼ), g2)
/// - Non-membership proofs include valid Schnorr proofs and pairing checks
pub fn verifyzk<T: Curve>(pk: &Pk<T>, commitment: T::G1, pi_sj: Option<(T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>,
kj: T::Scalar, witness: T::G1, phi_hat_kj: Option<T::Scalar>) -> bool {

    if phi_hat_kj.is_some() {
        let phi_hat_kj= phi_hat_kj.expect("invalid state");
        return verifyeval(pk, commitment, kj, T::scalar_from_literal(&0), phi_hat_kj, witness);
    }
    // always revealing phi_hat_kj allows us to use the verifyeval function above, such that the commiter cannot deny kj is in the set


    if pi_sj.is_none() {
        return false
    } 

    let (proof, n1, n2, s1, s2) = pi_sj.expect("invalid state");

    // commiter lied, phi(kj) is in their set
    if n1 == T::g1mul(&s1, &T::g1()) {
		return false
	}
    
    // we require both proofs to be valid
    if !schnorr_verify::<T>(pk, proof, n1, n2, s1, s2) {
    	return false 
    }


    let left = T::pairing(&T::g1sub(&commitment, &proof), &T::g2());
    let right = T::pairing(&witness, &T::g2sub(&pk.alpha_g2, &T::g2mul(&kj, &T::g2())));
    
    left == right
}


// private helper functions

fn verifyeval<T: Curve>(pk: &Pk<T>, commitment: T::G1, kj: T::Scalar, phi_kj: T::Scalar, phi_hat_kj: T::Scalar, witness: T::G1) -> bool {
    
    let left = T::pairing(&witness, &T::g2sub(&pk.alpha_g2, &T::g2mul(&kj, &T::g2())));

    let ys = T::g1add(&T::g1mul(&phi_kj, &T::g1()), &T::g1mul(&phi_hat_kj, &pk.h1));

    let right = T::pairing(&T::g1sub(&commitment, &ys), &T::g2());
    
    left == right
}

fn schnorr_proof<T: Curve>(pk: &Pk<T>, a: T::Scalar, b: T::Scalar, random: &mut Vec<u128>) -> (T::G1, T::G1, T::Scalar, T::Scalar) {
    let r1 = random.pop().expect("not enough randomness provided");
    let r2 = random.pop().expect("not enough randomness provided");
	
    let r1 = T::scalar_from_literal(&r1); 
    let r2 = T::scalar_from_literal(&r2); 

    let n1 = T::g1mul(&r1, &T::g1());
    let n2 = T::g1mul(&r2, &pk.h1);
    
    let z1 = T::g1mul(&a, &T::g1());
    let z2 = T::g1mul(&b, &pk.h1);
    
    let z = T::g1add(&z1, &z2);

    let c = T::fiat_shamir_hash(z, n1, n2, pk.h1);

    let s1 = r1 - c * a; 
    let s2 = r2 - c * b; 

    (n1, n2, s1, s2)
}

fn schnorr_verify<T: Curve>(pk: &Pk<T>, z: T::G1, n1: T::G1, n2: T::G1, s1: T::Scalar, s2: T::Scalar) -> bool {
    
    let c = T::fiat_shamir_hash(z, n1, n2, pk.h1);

    let left  = T::g1add(&n1, &n2);

    let s1 = T::g1mul(&s1, &T::g1());

    let s2 = T::g1mul(&s2, &pk.h1);
    
    let z = T::g1mul(&c, &z);

    let right = T::g1add(&T::g1add(&s1, &s2), &z);

    left == right
}

fn commit_poly<T: Curve>(polynomial: &Vec<T::Scalar> , pk: &Vec<T::G1>, generator: T::G1) -> T::G1 {
    // commit to the original polynomial
    let mut commitment = T::g1mul(&T::scalar_from_literal(&0), &generator);
    
    let difference = pk.len() - polynomial.len();
    for i in 0..polynomial.len() { 
        let power_index = difference + i;
        
        let current= T::g1mul(&polynomial[i], &pk[power_index]);
        commitment = T::g1add(&commitment, &current);
    };
    commitment
}

// applies the polynomial to input x
fn apply<T: Curve>(polynomial: &Vec<T::Scalar>, x: &T::Scalar) -> T::Scalar {
    let mut result= T::scalar_from_literal(&0);
    
    
    for i in 0..polynomial.len() {
        let term = polynomial[polynomial.len()-1-i] * T::scalar_pow(x, &(i as u128));
        result = result + term;
    }

    result
}

// multiply two polynomials
fn multiply<T: Curve>(f: &Vec<T::Scalar>, g: &Vec<T::Scalar>) -> Vec<T::Scalar> {
    let mut result = vec![T::scalar_from_literal(&0);f.len() + g.len() - 1];

    for (i, x) in f.iter().enumerate() {
        for (j, y) in g.iter().enumerate() {
            let current = result[i + j];
            result[i + j] = current + x.clone() * y.clone();
        }
    } 
    result
}

fn create_psi<T: Curve>(f: &Vec<T::Scalar>, f_x0: T::Scalar, x0: T::Scalar) -> Vec<T::Scalar> {
    
    // create a new polynomial with a root at x0
    let mut r: Vec<T::Scalar> = f.clone();
    let last_index = r.len() - 1;
    r[last_index] = r[last_index] - f_x0;

    
    let mut q: Vec<T::Scalar> = Vec::new();
    q.push(r[0]);

    //divide the polynomial r by (x - x0)
    for i in 0..r.len()-1 {
        let next_term = q[i]*x0+r[i+1];
        q.push(next_term);
    }
    
    q.pop();
    
    q
}

//creates the witness g^psi(i)h^psi_hat(i)
fn create_witness<T: Curve>(phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, i: T::Scalar, pk: &Pk<T>) 
-> (T::Scalar, T::Scalar, T::Scalar, T::G1) {

    let phi_i  = apply::<T>(&phi, &i);
    let phi_hat_i = apply::<T>(&phi_hat, &i);

    let psi = create_psi::<T>(&phi, phi_i, i);
    let psi_hat = create_psi::<T>(&phi_hat, phi_hat_i, i);

        
    let mut witness = commit_poly::<T>(&psi, &pk.g_powers, T::g1());
    witness = T::g1add(&witness, &commit_poly::<T>(&psi_hat, &pk.h_powers, pk.h1));

    return (i, phi_i, phi_hat_i, witness);
}




use hacspec_bls12_381::*;

    fn g1sub(x: G1, y: G1) -> G1 {
        g1add(x, g1neg(y))
    }

    fn g2sub(x: G2, y: G2) -> G2 {
        g2add(x, g2neg(y))
    }

    fn g1() -> G1 {
    (Fp::from_hex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
     Fp::from_hex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), false)
    }
    fn g2() -> G2 {
    ((Fp::from_hex("24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
      Fp::from_hex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")),
     (Fp::from_hex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
      Fp::from_hex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")), false)
    }
    
    struct PkVerifiable {    
        g_powers: Vec<G1>,
        h_powers: Vec<G1>,
        h1: G1,
        alpha_g2: G2
    }
    

    #[hax_lib::requires(pk.len() >= polynomial.len())]
    fn commit_poly_verifiable(polynomial: &Vec<Scalar> , pk: &Vec<G1>, generator: G1) -> G1 {
        // commit to the original polynomial
        let mut commitment = g1sub(generator, generator);
        
        let difference = pk.len() - polynomial.len();
        for i in 0..polynomial.len() { 
            let power_index = difference + i;
            
            let current = g1mul(polynomial[i], pk[power_index]);
            commitment = g1add(commitment, current);
        };
        commitment
    }


    fn verifyeval_verifiable(pk: &PkVerifiable, commitment: G1, kj: Scalar, phi_kj: Scalar, phi_hat_kj: Scalar, witness: G1) -> bool {
        
        let left = pairing(witness, g2sub(pk.alpha_g2, g2mul(kj, g2())));

        let ys = g1add(g1mul(phi_kj, g1()), g1mul(phi_hat_kj, pk.h1));

        let right = pairing(g1sub(commitment, ys), g2());
        
        left == right
    }
    
    fn g1_to_byte_seq_verifiable(g: G1) -> hacspec_lib::ByteSeq {
        let (x, y, inf) = g;
        let x_bytes = x.to_byte_seq_be();  
        let result= x_bytes.concat(&y.to_byte_seq_be());
        
        let mut inf_bytes = hacspec_lib::U8::zero();
        
        if inf {
            inf_bytes = hacspec_lib::U8::one();
        }
        
        result.push(&inf_bytes)
    }

    fn fiat_shamir_hash_verifiable(z: G1, n1: G1, n2: G1, h: G1) -> Scalar {
        let g = g1_to_byte_seq_verifiable(g1());
        let h = g1_to_byte_seq_verifiable(h);
        let z = g1_to_byte_seq_verifiable(z);
        let n1 = g1_to_byte_seq_verifiable(n1);
        let n2 = g1_to_byte_seq_verifiable(n2);

        let bytes = g.concat(&h).concat(&z).concat(&n1).concat(&n2);
        
        let digest = hacspec_sha256::hash(&bytes);

        Scalar::from_byte_seq_be(&digest)
    } 

    fn schnorr_verify_verifiable(pk: &PkVerifiable, z: G1, n1: G1, n2: G1, s1: Scalar, s2: Scalar) -> bool {
        
        let c = fiat_shamir_hash_verifiable(z, n1, n2, pk.h1);

        let left  = g1add(n1, n2);

        let s1 = g1mul(s1, g1());

        let s2 = g1mul(s2, pk.h1);
        
        let z = g1mul(c, z);

        let right = g1add(g1add(s1, s2), z);

        left == right
    }




#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;
    use quickcheck::TestResult;
    use rand::random;
    use super::*;

    // Generate random numbers for testing purposes
    // Production code should use cryptographic randomness
    // to maintain security properties
    fn generate_randomness(n: usize) -> Vec<u128> {
        let mut rand: Vec<u128> = Vec::with_capacity(n); 
        for _ in 0..n {
            let mut r = random();
            while r == 0 {
                r = random();
            }
            rand.push(r)
        }
        rand
    }

    
    // this tests of the completeness standard schnorr proof
    #[quickcheck]
    fn test_schnorr_verification(a: u128, b: u128) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

        let mut random = generate_randomness(5);
        
        let pk: Pk<Curve> = setup(1, &mut random);

        
        let a = Curve::scalar_from_literal(&a);
        let b = Curve::scalar_from_literal(&b);
            
        let p1 = Curve::g1mul(&a, &Curve::g1());
        let p2 = Curve::g1mul(&b, &pk.h1);
        
        let proof = Curve::g1add(&p1, &p2);

            
        let (n1, n2, s1, s2) = schnorr_proof(&pk, a, b, &mut random);
        

        schnorr_verify::<Curve>(&pk, proof, n1, n2, s1, s2)
    }


    // this tests soundness of the standard schnorr proof
    #[quickcheck]
    fn test_schnorr_forgery(a: u128, b: u128) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

		let mut random = generate_randomness(20);

		let pk: Pk<Curve> = setup(1, &mut random);

		let a = Curve::scalar_from_literal(&a);
		let b = Curve::scalar_from_literal(&b);
			
		let p1 = Curve::g1mul(&a, &Curve::g1());
		let p2 = Curve::g1mul(&b, &pk.h1);
		
		let proof = Curve::g1add(&p1, &p2);

		// fake knowledge of a by simulating guessing it
		let a = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));

			
		let (n1, n2, s1, s2) = schnorr_proof(&pk, a, b, &mut random);
		

		! schnorr_verify::<Curve>(&pk, proof, n1, n2, s1, s2)
    }

    // this tests completeness of the nonzero proof
	#[quickcheck]
	fn test_schnorr_nonzero_proof(b: u128) -> bool {
		use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

		let mut random = generate_randomness(20);

		let pk: Pk<Curve> = setup(1, &mut random);

		let a = 0;
		let a = Curve::scalar_from_literal(&a);
		let b = Curve::scalar_from_literal(&b);
			
		let p1 = Curve::g1mul(&a, &Curve::g1());
		let p2 = Curve::g1mul(&b, &pk.h1);
		
		let _proof = Curve::g1add(&p1, &p2);

		let (n1, _n2, s1, _s2) = schnorr_proof(&pk, a, b, &mut random);
		
		n1 == Curve::g1mul(&s1, &Curve::g1())
	}

    // this tests soundness of the nonzero proof
	#[quickcheck]
	fn test_schnorr_zero_proof(b: u128, a: u128) -> TestResult {
        if a == 0 {
            return TestResult::discard()
        }
		use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

		let mut random = generate_randomness(20);

		let pk: Pk<Curve> = setup(1, &mut random);

		let a = Curve::scalar_from_literal(&a);
		let b = Curve::scalar_from_literal(&b);
			
		let p1 = Curve::g1mul(&a, &Curve::g1());
		let p2 = Curve::g1mul(&b, &pk.h1);
		
		let _proof = Curve::g1add(&p1, &p2);

		let (n1, _n2, s1, _s2) = schnorr_proof(&pk, a, b, &mut random);
		
		if n1 == Curve::g1mul(&s1, &Curve::g1()) {
            return TestResult::failed();
        }

        TestResult::passed()
	}
    
    
    // this tests completeness

    #[quickcheck] 
    fn test_kzg_verification(is_in_set: bool, degree: u8) -> bool {
        // use curve::SpecCurve as Curve;
        use curve::FastCurve as Curve;

        let degree = (degree % 10) as usize;

        let mut random = generate_randomness(degree + 1); 
        

        let mut set = HashSet::new();

        let mut kj = Curve::scalar_from_literal(&0);
        for _ in 0..degree {
            kj = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));
            set.insert(kj);
        }

        if ! is_in_set {
            kj = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));
        }
 
        let mut random = generate_randomness(degree + 5);
        

        let pk: Pk<Curve> = setup(degree as u128, &mut random);
        

        let (commitment, phi, phi_hat) = commitzk(&pk, &set, &mut random);
        
        let (kj, witness, phi_hat_kj, pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random);

        let result = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
        
        return result;
    }

    
    
    // this tests soundness
    #[quickcheck] 
    fn test_kzg_forgery(is_in_set: bool, degree: u8) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

        let degree = (degree % 10) as usize;

        let mut random = generate_randomness(degree + 1); 
        
        let mut set = HashSet::new();

        let mut kj = Curve::scalar_from_literal(&0);
        for _ in 0..degree {
            kj = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));
            set.insert(kj);
        }

        if ! is_in_set {
            kj = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));
        }
 
        let mut random = generate_randomness(degree + 5);
        

        let pk: Pk<Curve> = setup(degree as u128, &mut random);
        

        let (commitment, phi, phi_hat) = commitzk(&pk, &set, &mut random); 
    
        let (kj, _witness, phi_hat_kj, pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random);
        
        
        let mut random = generate_randomness(degree);

        let mut forged_poly = Vec::new(); 
        for _ in 0..degree {
            forged_poly.push(Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided")));
        }
        
        let witness = Curve::g1mul(&apply::<Curve>(&forged_poly, &kj), &Curve::g1());


        let result = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);

        return ! result
    }
	
    

    // this tests that if the prover just lies about
    // phi(kj) neq 0
    // then the verification fails
    // tests for soundness
    #[quickcheck] 
    fn test_kzg_false_claim() -> bool {
        // use curve::SpecCurve as Curve;
        use curve::FastCurve as Curve;

        let degree = 10;

        let mut random = generate_randomness(degree + 1); 
        
        let mut set = HashSet::new();

        let mut kj = Curve::scalar_from_literal(&0);
        for _ in 0..degree {
            kj = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));
            set.insert(kj);
        }
 
        let mut random = generate_randomness(degree + 5);
        

        let pk: Pk<Curve> = setup(degree as u128, &mut random);
        

        let (commitment, phi, phi_hat) = commitzk(&pk, &set, &mut random); 
    
        let (kj, witness, _phi_hat_kj, _pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random);
		

		let phi_kj =  apply::<Curve>(&phi, &kj);
		let phi_hat_kj =  apply::<Curve>(&phi_hat, &kj);

		let p1 = Curve::g1mul(&phi_kj, &Curve::g1());
		let p2 = Curve::g1mul(&phi_hat_kj, &pk.h1);
		let proof = Curve::g1add(&p1, &p2);


		let (n1, n2, s1, s2) = schnorr_proof(&pk, phi_kj, phi_hat_kj, &mut random);
		let pi = (proof, n1, n2, s1, s2);


        let result = verifyzk(&pk, commitment, Some(pi), kj, witness, None);

        return ! result
    }
	
}
