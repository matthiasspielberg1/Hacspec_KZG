//! # Elliptic Curve Abstraction for Zero-Knowledge Proofs
//!
//! This module provides a generic abstraction over pairing-friendly elliptic curves,
//! allowing the kzg commitment scheme to use different curve implementations
//! based on performance, security, and verification requirements.
//!
//! ## Curve Trait
//!
//! The `Curve` trait defines the essential operations needed for polynomial commitments
//! and zero-knowledge proofs:
//! - **Group operations**: Addition, subtraction, and scalar multiplication in G₁ and G₂
//! - **Scalar arithmetic**: Field operations for polynomial coefficients
//! - **Bilinear pairings**: Maps e(G₁, G₂) → Gₜ for verification equations
//! - **Hash functions**: Fiat-Shamir transformation for non-interactive proofs
//!
//! ## Available Implementations
//!
//! ### SpecCurve
//! A specification-friendly implementation using `hacspec_bls12_381` that prioritizes:
//! - **Formal verification**: Compatible with formal analysis tools
//! - **Auditability**: Clear, readable implementation for security reviews
//! - **Specification compliance**: Follows standards precisely
//!
//! ### FastCurve  
//! A performance-optimized implementation using `blstrs` that provides:
//! - **High performance**: Optimized for production deployments
//! - **Constant-time operations**: Resistance to timing attacks
//! - **Assembly optimizations**: Hardware-accelerated operations where available
//!

use std::ops::{Add, Mul, Sub};
use std::hash::{Hash, DefaultHasher, Hasher};
use std::fmt::{Display, Debug};

mod spec {
   pub use hacspec_bls12_381::*; 
   
}
mod sha {
    pub use hacspec_sha256::*;
}
use blstrs;

pub trait Curve {
    type G1:
        Eq +
        Copy + 
        Debug;
    type G2:
        Eq +
        Copy + 
        Debug;
    type Scalar:
        Eq +
        Add<Output = Self::Scalar> +
        Sub<Output = Self::Scalar> +
        Mul<Output = Self::Scalar> +
        Copy +
        //hash is needed so we can construct a set
        //using hashing since fast implemenatation does 
        //not implement ordering
        Hash + 
        Display +
        Debug;
    type Element:
        Eq + 
        Debug;

    fn scalar_from_literal(x: &u128) -> Self::Scalar;
    
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar;

    fn g1mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1;
    fn g2mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2;

    fn g1add(x: &Self::G1, y: &Self::G1) -> Self::G1;
    fn g2add(x: &Self::G2, y: &Self::G2) -> Self::G2;

    fn g1sub(x: &Self::G1, y: &Self::G1) -> Self::G1;
    fn g2sub(x: &Self::G2, y: &Self::G2) -> Self::G2;
    
    fn g1() -> Self::G1;
    fn g2() -> Self::G2;
    
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element;

    fn fiat_shamir_hash(z: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar; 
}



fn g1_to_byte_seq(g: spec::G1) -> hacspec_lib::ByteSeq {
    let (x, y, inf) = g;
    let x_bytes = x.to_byte_seq_be();  
    let result= x_bytes.concat(&y.to_byte_seq_be());
    
    let mut inf_bytes = hacspec_lib::U8::zero();
    
    if inf {
        inf_bytes = hacspec_lib::U8::one();
    }
    
    result.push(&inf_bytes)
}



pub struct FastCurve;
pub struct SpecCurve;


impl Curve for SpecCurve {

    type G1 = spec::G1;
    type G2 = spec::G2;
    type Scalar = spec::Scalar;
    type Element = spec::Fp12;

    fn scalar_from_literal(x: &u128) -> Self::Scalar {
        spec::Scalar::from_literal(x.clone()) 
    }
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar {
        x.pow(y.clone())
    }
    fn g1mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1 {
        spec::g1mul(x.clone(), y.clone())    
    }
    fn g2mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2 {
        spec::g2mul(x.clone(), y.clone())
    }
    fn g1add(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        spec::g1add(x.clone(), y.clone())
    }
    fn g2add(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        spec::g2add(x.clone(), y.clone()) 
    }
    fn g1sub(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        spec::g1add(x.clone(), spec::g1neg(y.clone()))
    }
    fn g2sub(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        spec::g2add(x.clone(), spec::g2neg(y.clone()))
    }
    fn g1() -> Self::G1 {
    (spec::Fp::from_hex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
     spec::Fp::from_hex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), false)
    }
    fn g2() -> Self::G2 {
    ((spec::Fp::from_hex("24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
      spec::Fp::from_hex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")),
     (spec::Fp::from_hex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
      spec::Fp::from_hex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")), false)
    }
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element {
        spec::pairing(x.clone(), y.clone())
    }
    
    fn fiat_shamir_hash(z: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar {
        let g = g1_to_byte_seq(Self::g1());
        let h = g1_to_byte_seq(h);
        let z = g1_to_byte_seq(z);
        let n1 = g1_to_byte_seq(n1);
        let n2 = g1_to_byte_seq(n2);

        let bytes = g.concat(&h).concat(&z).concat(&n1).concat(&n2);
        
        let digest = sha::hash(&bytes);

        spec::Scalar::from_byte_seq_be(&digest)
    } 
}



use blstrs::G1Projective;
use group::{ff::{Field, PrimeField}, Group};

impl Curve for FastCurve {
    type G1 = blstrs::G1Projective;
    type G2 = blstrs::G2Projective;
    type Scalar = blstrs::Scalar;
    type Element = blstrs::Gt;
 
    fn scalar_from_literal(x: &u128) -> Self::Scalar {
        blstrs::Scalar::from_u128(x.clone())
    }
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar {
        let big_end = ((y & 0xFFFFFFFFFFFFFFFF0000000000000000) >> 64) as u64;
        let small_end= (y & 0x0000000000000000FFFFFFFFFFFFFFFF) as u64;
        let exp = vec![small_end, big_end];
        x.pow(exp)
    }
    fn g1mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1 {
        y.mul(x)
    }
    fn g2mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2 {
        y.mul(x)
    }
    fn g1add(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        x + y
    }
    fn g2add(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        x + y
    }
    fn g1sub(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        x - y
    }
    fn g2sub(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        x - y
    }
    fn g1() -> Self::G1 {
        G1Projective::generator()
    }
    fn g2() -> Self::G2 {
       blstrs::G2Projective::generator() 
    }
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element {
        let left = blstrs::G1Affine::from(x);
        let right = blstrs::G2Affine::from(y);
        blstrs::pairing(&left, &right)
    }
    
    fn fiat_shamir_hash(z: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar {
        let mut hasher = DefaultHasher::new();
        // the fast library only provides the tostring method for 
        
        z.to_string().hash(&mut hasher);
        n1.to_string().hash(&mut hasher);
        n2.to_string().hash(&mut hasher);
        h.to_string().hash(&mut hasher);
        
        let res = hasher.finish();
        Self::Scalar::from(res)
    } 
}


#[cfg(test)] 
mod test {
    use quickcheck_macros::quickcheck;

    use rand::random;
    use super::*;

    // generates n random u128
    // lets us avoid generating randomness directly in our kzg implementation
    fn generate_randomness(n: usize) -> Vec<u128> {
        let mut rand: Vec<u128> = Vec::with_capacity(n); 

        for _ in 0..n {
            rand.push(random())
    }
    rand
    }

    #[quickcheck]
    fn test_trait_scalar_from_literal(base: u128) -> bool { 
        let specscalar = SpecCurve::scalar_from_literal(&base);
        let fastscalar = FastCurve::scalar_from_literal(&base);
        
        let spec = specscalar.to_be_bytes();
        let fast = fastscalar.to_bytes_be().to_vec();

        spec == fast
    } 
    
    #[quickcheck]
    fn test_trait_scalar_power(base: u128, exp: u128) -> bool { 
        let specscalar = SpecCurve::scalar_from_literal(&base);
        let fastscalar = FastCurve::scalar_from_literal(&base);
        
        let specpow = SpecCurve::scalar_pow(&specscalar, &exp);
        let fastpow = FastCurve::scalar_pow(&fastscalar, &exp);

        
        let spec = specpow.to_be_bytes();
        let fast = fastpow.to_bytes_be().to_vec();

        spec == fast
    } 

    #[quickcheck]
    fn test_trait_commitment() -> bool {
        use std::collections::HashSet;

        
        let poly = vec![1, 12, 43, 8423790, 27983, 83, 89203, 12912987798231, 65];
        let degree = poly.len() + 2;
        
        // we use the same random values for both implemtations
        let fast_random = generate_randomness(poly.len() + 5);
        let spec_random = fast_random.clone();


        // commiting to the fast implementation
        let mut random = fast_random;
        let pk = crate::setup::<FastCurve>(degree as u128, &mut random);
        let mut set = HashSet::new();
        for i in poly.iter() {
            set.insert(FastCurve::scalar_from_literal(i)); 
        } 
        let (fast_commitment, _, _) = crate::commitzk(&pk, &set, &mut random);
        let fast_commitment = blstrs::G1Affine::from(fast_commitment);
        
        
        //commiting to the specification implementation
        let mut random = spec_random;
        let pk = crate::setup::<SpecCurve>(degree as u128, &mut random);
        let mut set = HashSet::new();
        for i in poly.iter() {
            set.insert(SpecCurve::scalar_from_literal(i)); 
        }
        let (spec_commitment, _, _) = crate::commitzk(&pk, &set, &mut random); 
        
        
        // since the bls implementations should be equivalent and we use the same randomness
        // we expect the commitment to be the same
        let (s_x, s_y, _) = spec_commitment; 
        let x_eq = s_x.to_be_bytes() == fast_commitment.x().to_bytes_be();
        let y_eq = s_y.to_be_bytes() == fast_commitment.y().to_bytes_be();

        x_eq && y_eq
    }    
}