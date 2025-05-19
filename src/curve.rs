use std::{hash::{Hash, Hasher}, ops::{Add, Mul, Sub}};

mod Spec {
   pub use hacspec_bls12_381::*; 
   
}
mod Sha {
    pub use hacspec_sha256::*;
}


pub trait Curve {
    type G1:
        Eq +
        Copy;
    type G2:
        Eq +
        Copy;
    type Scalar:
        Eq +
        Add<Output = Self::Scalar> +
        Sub<Output = Self::Scalar> +
        Mul<Output = Self::Scalar> +
        Copy +
        //hash is needed so we can construct a set
        //using hashing since fast implemenatation does 
        //not implement ordering
        std::hash::Hash;
    type Element:
        Eq;

    fn scalar_from_literal(x: &u128) -> Self::Scalar;
    
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar;

    fn g1_mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1;
    fn g2_mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2;

    fn g1_add(x: &Self::G1, y: &Self::G1) -> Self::G1;
    fn g2_add(x: &Self::G2, y: &Self::G2) -> Self::G2;

    fn g1_sub(x: &Self::G1, y: &Self::G1) -> Self::G1;
    fn g2_sub(x: &Self::G2, y: &Self::G2) -> Self::G2;
    
    fn g1() -> Self::G1;
    fn g2() -> Self::G2;
    
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element;

    fn fiat_shamir_hash(z1: Self::G1, z2: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar;
    
}



fn g1_to_byte_seq(g: Spec::G1) -> hacspec_lib::ByteSeq {
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

    type G1 = Spec::G1;
    type G2 = Spec::G2;
    type Scalar = Spec::Scalar;
    type Element = Spec::Fp12;

    fn scalar_from_literal(x: &u128) -> Self::Scalar {
        Spec::Scalar::from_literal(x.clone()) 
    }
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar {
        x.pow(y.clone())
    }
    fn g1_mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1 {
        Spec::g1mul(x.clone(), y.clone())    
    }
    fn g2_mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2 {
        Spec::g2mul(x.clone(), y.clone())
    }
    fn g1_add(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        Spec::g1add(x.clone(), y.clone())
    }
    fn g2_add(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        Spec::g2add(x.clone(), y.clone()) 
    }
    fn g1_sub(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        Spec::g1add(x.clone(), Spec::g1neg(y.clone()))
    }
    fn g2_sub(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        Spec::g2add(x.clone(), Spec::g2neg(y.clone()))
    }
    fn g1() -> Self::G1 {
    (Spec::Fp::from_hex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
     Spec::Fp::from_hex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), false)
    }
    fn g2() -> Self::G2 {
    ((Spec::Fp::from_hex("24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
      Spec::Fp::from_hex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")),
     (Spec::Fp::from_hex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
      Spec::Fp::from_hex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")), false)
    }
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element {
        Spec::pairing(x.clone(), y.clone())
    }
    
    fn fiat_shamir_hash(z1: Self::G1, z2: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar {
        let g = g1_to_byte_seq(Self::g1());
        let h = g1_to_byte_seq(h);
        let z1 = g1_to_byte_seq(z1);
        let z2 = g1_to_byte_seq(z2);
        let n1 = g1_to_byte_seq(n1);
        let n2 = g1_to_byte_seq(n2);

        let bytes = g.concat(&h).concat(&z1).concat(&z2).concat(&n1).concat(&n2);
        
        let digest = Sha::hash(&bytes);

        Spec::Scalar::from_byte_seq_be(&digest)
    } 
}


impl Curve for FastCurve {
   type G1 = bls12_381::G1Projective;
   type G2 = bls12_381::G2Projective;
   type Scalar = bls12_381::Scalar;
   type Element = bls12_381::Gt;
   
    fn scalar_from_literal(x: &u128) -> Self::Scalar {
        let big_end = ((x & 0xFFFFFFFFFFFFFFFF0000000000000000) >> 64) as u64;
        let small_end= (x & 0x0000000000000000FFFFFFFFFFFFFFFF) as u64;
        bls12_381::Scalar::from_raw([small_end, big_end, 0, 0])
    }
    fn scalar_pow(x: &Self::Scalar, y: &u128) -> Self::Scalar {
        //extract the u128 into two u64 consisting of the upper and lower parts
        let big_end = ((y & 0xFFFFFFFFFFFFFFFF0000000000000000) >> 64) as u64;
        let small_end= (y & 0x0000000000000000FFFFFFFFFFFFFFFF) as u64;
        x.pow(&[small_end, big_end, 0, 0])
    }
    fn g1_mul(x: &Self::Scalar, y: &Self::G1) -> Self::G1 {
        y.mul(x)
    }
    fn g2_mul(x: &Self::Scalar, y: &Self::G2) -> Self::G2 {
        y.mul(x)
    }
    fn g1_add(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        x + y
    }
    fn g2_add(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        x + y
    }
    fn g1_sub(x: &Self::G1, y: &Self::G1) -> Self::G1 {
        x - y
    }
    fn g2_sub(x: &Self::G2, y: &Self::G2) -> Self::G2 {
        x - y
    }
    fn g1() -> Self::G1 {
        bls12_381::G1Projective::generator()
    }
    fn g2() -> Self::G2 {
       bls12_381::G2Projective::generator() 
    }
    fn pairing(x: &Self::G1, y: &Self::G2) -> Self::Element {
        let left = bls12_381::G1Affine::from(x);
        let right = bls12_381::G2Affine::from(y);
        bls12_381::pairing(&left, &right)
    }
    
    fn fiat_shamir_hash(z1: Self::G1, z2: Self::G1, n1: Self::G1, n2: Self::G1, h: Self::G1) -> Self::Scalar {
        let mut hasher = std::hash::DefaultHasher::new();
        // the fast library only provides the tostring method for 
        // extracting the value of the g1
        z1.to_string().hash(&mut hasher);
        z2.to_string().hash(&mut hasher);
        n1.to_string().hash(&mut hasher);
        n2.to_string().hash(&mut hasher);
        h.to_string().hash(&mut hasher);
        
        let res = hasher.finish();
        bls12_381::Scalar::from(res)
    } 
}



#[cfg(test)] 
mod test {
    use quickcheck_macros::quickcheck;

    // use crate::curve::{Curve, SpecCurve};
    use super::*;

    #[quickcheck]
    fn test_trait_scalar_from_literal(base: u128) -> bool {

        
        let specscalar = SpecCurve::scalar_from_literal(&base);
        let fastscalar = FastCurve::scalar_from_literal(&base);
        
        let spec = specscalar.to_le_bytes();
        let fast = fastscalar.to_bytes().to_vec();

        spec == fast
    } 
    
    #[quickcheck]
    fn test_trait_scalar_power(base: u128, exp: u128) -> bool {

        
        let specscalar = SpecCurve::scalar_from_literal(&base);
        let fastscalar = FastCurve::scalar_from_literal(&base);
        
        let specpow = SpecCurve::scalar_pow(&specscalar, &exp);
        let fastpow = FastCurve::scalar_pow(&fastscalar, &exp);

        
        let spec = specpow.to_le_bytes();
        let fast = fastpow.to_bytes().to_vec();

        spec == fast
    } 

    
    

}