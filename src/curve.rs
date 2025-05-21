use std::{hash::{Hash, Hasher}, ops::{Add, Mul, Sub}};

mod Spec {
   pub use hacspec_bls12_381::*; 
   
}
mod Sha {
    pub use hacspec_sha256::*;
}
use blstrs;

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
        Self::Scalar::from(res)
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
    fn test_trait_commitment(scalar: u128, kj_literal: u128) -> bool {
        use std::collections::HashSet;
        use std::time;

        
        let poly = vec![1, 12, 43, 8423790, 27983, 83, 89203, 12912987798231, 65];
        let degree = poly.len() + 2;
        
        let mut random = crate::generate_randomness(poly.len() + 5);

        let pk = crate::setup::<FastCurve>(degree as u128, &mut random);
        let mut set = HashSet::new();
        for i in poly.iter() {
            set.insert(FastCurve::scalar_from_literal(i)); 
        }
        
        let fast_start = time::Instant::now();
        let (commitment, phi, phi_hat) = crate::commitzk(&pk, &set, &mut random);
        let kj = FastCurve::scalar_from_literal(&kj_literal); 
        let (kj, witness, phi_hat_kj, pi_sj) = crate::queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random); 
        let fast_result = crate::verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
        let fast_time = fast_start.elapsed();
        
        println!("fast implementation done in {}", fast_time.as_millis());
        
        let mut random = crate::generate_randomness(poly.len() + 5);
        let pk = crate::setup::<SpecCurve>(degree as u128, &mut random);
        let mut set = HashSet::new();
        for i in poly.iter() {
            set.insert(SpecCurve::scalar_from_literal(i)); 
        }
        let spec_start = time::Instant::now();
        let (commitment, phi, phi_hat) = crate::commitzk(&pk, &set, &mut random);
        let kj = SpecCurve::scalar_from_literal(&kj_literal); 
        let (kj, witness, phi_hat_kj, pi_sj) = crate::queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random); 
        let slow_result = crate::verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
        let spec_time = spec_start.elapsed();
        
        println!("slow implementation done in {}", spec_time.as_secs());


        let result = fast_result == slow_result;

        println!("result: {result}");
        result
    }
    
    #[test]
    fn benchmark() { 
        use std::collections::HashSet;
        use std::time::{Instant, Duration};
        
        struct Timer(Vec<Duration>, Vec<Duration>, Vec<Duration>, Vec<Duration>);


        
        

        fn benchmark_single_iteration<T: Curve>(poly: &Vec<u128>, times: &mut Timer) {
            let degree = poly.len() + 2; 
            let mut random = crate::generate_randomness(poly.len() + 6);
             
            let kj_literal = random.pop().expect("not enough randomness provided"); 

            let mut timer = Instant::now();
            let pk = crate::setup::<T>(degree as u128, &mut random);
            times.0.push(timer.elapsed());

            let mut set = HashSet::new();
            for i in poly.iter() {
                set.insert(T::scalar_from_literal(i)); 
            }
            
            timer = Instant::now();
            let (commitment, phi, phi_hat) = crate::commitzk(&pk, &set, &mut random);
            times.1.push(timer.elapsed());

            let kj = T::scalar_from_literal(&kj_literal); 

            timer = Instant::now();
            let (kj, witness, phi_hat_kj, pi_sj) = crate::queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random); 
            times.2.push(timer.elapsed());
            
            timer = Instant::now();
            let fast_result = crate::verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
            times.3.push(timer.elapsed());    
            }
        
        
        fn print_timer(implementation: &str, length: usize, iterations: u128,  timer: Timer) {
            println!("{implementation} implementation with {length} length polynomials and corresponding setup"); 
            
            let setup_time: u128 = timer.0.iter().map(|x| {x.as_millis()}).sum::<u128>() / iterations;
        
            let mut total = setup_time;
            println!("setup phase: \t\t{}ms", setup_time);
            
            let commit_time: u128 = timer.1.iter().map(|x| {x.as_millis()}).sum::<u128>() / iterations;
            
            let proof_gen_time: u128 = commit_time + timer.2.iter().map(|x| {x.as_millis()}).sum::<u128>() / iterations;
            total += proof_gen_time;
            println!("query phase: \t\t{}ms", proof_gen_time);
            
            let verification_time: u128 = timer.3.iter().map(|x| {x.as_millis()}).sum::<u128>() / iterations;
            total += verification_time;
            println!("verification phase: \t{}ms", verification_time);
            
            println!("\n");
        }
            
        println!(); 
        for i in [5, 10, 20, 50] {
            let poly = crate::generate_randomness(i.clone());
                
            let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for _ in 0..20 {
                benchmark_single_iteration::<FastCurve>(&poly, &mut timer);
            }
            print_timer("fast", i, 20, timer);
        }     
        
        println!("\n");
        for i in [5, 10, 20, 50] {
            let poly = crate::generate_randomness(i.clone());
            let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for _ in 0..5 {
                benchmark_single_iteration::<SpecCurve>(&poly, &mut timer);
            }
            print_timer("specification", i, 5, timer);
        }     
    }
}