#![allow(unused_variables)]
#![allow(dead_code)]
mod curve;

use hacspec_bls12_381::*;
use hacspec_sha256::hash;
use hacspec_lib::*;
use std::collections::{BTreeSet, HashSet};
use rand::Rng;
use curve::Curve;

//TODO
// sample a vector of random numbers really often, then pass that stream to functions,
// so we dont rely on proving random numbers


fn g1sub (p: G1, q: G1) -> G1 {
    g1add(p, g1neg(q))
}

fn g2sub (p: G2, q: G2) -> G2 {
    g2add(p, g2neg(q))
}


// applies the polynomial to input x
fn apply<T: Curve>(polynomium: &Vec<T::Scalar>, x: &T::Scalar) -> T::Scalar {
    let mut result= T::scalar_from_literal(&0);

    for i in 0..polynomium.len() {
        let term = polynomium[polynomium.len()-1-i] * T::scalar_pow(x, &(i as u128));
        result = result + term;
    }

    result
}


struct Pk<T: Curve> {
    g_powers: Vec<T::G1>,
    h_powers: Vec<T::G1>,
    h1: T::G1,
    alpha_g2: T::G2
}


// multiply two polynomials
pub fn multiply<T: Curve>(f: &Vec<T::Scalar>, g: &Vec<T::Scalar>) -> Vec<T::Scalar> {
    let mut result = vec![T::scalar_from_literal(&0);f.len() + g.len() - 1];

    for (i, x) in f.iter().enumerate() {
        for (j, y) in g.iter().enumerate() {
            let current = result[i + j];
            result[i + j] = current + x.clone() * y.clone();
        }
    } 
    result
}

fn calculate_psi<T: Curve>(f: &Vec<T::Scalar>, f_x0: T::Scalar, x0: T::Scalar) -> Vec<T::Scalar> {
    
    // create a new polynomial with a root at x0
    let mut r: Vec<T::Scalar> = f.clone();
    let last_index = r.len() - 1;
    r[last_index] = r[last_index] - f_x0;

    
    let mut q: Vec<T::Scalar> = Vec::new();
    q.push(r[0]);

    //divide the polynoimium r by (x - x0)
    for i in 0..r.len()-1 {
        let next_term = q[i]*x0+r[i+1];
        q.push(next_term);
    }
    
    q.pop();
    
    q
}



fn commit_poly<T: Curve>(polynomium: &Vec<T::Scalar> , pk: &Vec<T::G1>, generator: T::G1) -> T::G1 {

    // commit to the original polynomial
    let mut commitment = T::g1_mul(&T::scalar_from_literal(&0), &generator);
    
    for i in 0..polynomium.len() { 
        let power_index = pk.len() - polynomium.len() + i;
        
        let current= T::g1_mul(&polynomium[i], &pk[power_index]);
        commitment = T::g1_add(&commitment, &current);
    };
    commitment
}

// fn fiat_shamir_hash(z1: G1, z2: G1, n1: G1, n2: G1, h: G1) -> Scalar {
//     let g = g1_to_byte_seq(g1());
//     let h = g1_to_byte_seq(h);
//     let z1 = g1_to_byte_seq(z1);
//     let z2 = g1_to_byte_seq(z2);
//     let n1 = g1_to_byte_seq(n1);
//     let n2 = g1_to_byte_seq(n2);

//     let bytes = g.concat(&h).concat(&z1).concat(&z2).concat(&n1).concat(&n2);
    
//     let digest = hash(&bytes);

//     Scalar::from_byte_seq_be(&digest)
// }


fn setup<T: Curve>(degree: u128) -> Pk<T> {
    let mut rng = rand::rng(); 

    // generate a random alpha value
    let alpha =  T::scalar_from_literal(&rng.random());

    let mut setup_g1 = Vec::new();
    let mut setup_h1 = Vec::new();
    
    // generate h from some random lambda
    let h = T::g1_mul(&T::scalar_from_literal(&rng.random()), &T::g1());

    for i in 0..degree+1 {
        let power: u128 = (degree - i).into();
        let alpha_power= T::scalar_pow(&alpha, &power);

        setup_g1.push(T::g1_mul(&alpha_power, &T::g1()));
        setup_h1.push(T::g1_mul(&alpha_power, &h));
    };
    
    let alpha_g2 = T::g2_mul(&alpha, &T::g2());

    Pk{g_powers : setup_g1, h_powers : setup_h1, h1 : h, alpha_g2}
}


// commit to the set
fn commitzk<T: Curve>(pk: &Pk<T>, set: &HashSet<T::Scalar>) -> (T::G1, Vec<T::Scalar>, Vec<T::Scalar>) {
    let mut phi = vec![T::scalar_from_literal(&1)];
    
    let zero = T::scalar_from_literal(&0);

    for i in set {
        let mul = vec![T::scalar_from_literal(&1),  zero - *i ];
        phi = multiply::<T>(&phi, &mul);
    }

    let mut phi_hat = vec![T::scalar_from_literal(&0); phi.len()];
    
    let mut rng = rand::rng();
    
    // create a random hiding polynomial
    for i in 0..phi_hat.len() {
        phi_hat[i] = T::scalar_from_literal(&rng.random());
    }

    
    let commitment = commit_poly::<T>(&phi, &pk.g_powers, T::g1());
    let hiding_commitment = commit_poly::<T>(&phi_hat, &pk.h_powers, pk.h1);

    
    (T::g1_add(&commitment, &hiding_commitment), phi, phi_hat)
}


//creates the witness g^psi(i)h^psi_hat(i)
fn create_witness<T: Curve>(phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, i: T::Scalar, pk: &Pk<T>) 
-> (T::Scalar, T::Scalar, T::Scalar, T::G1) {

    let phi_i  = apply::<T>(&phi, &i);
    let phi_hat_i = apply::<T>(&phi_hat, &i);


    let psi = calculate_psi::<T>(&phi, phi_i, i);
    let psi_hat = calculate_psi::<T>(&phi_hat, phi_hat_i, i);

        
    let mut witness = commit_poly::<T>(&psi, &pk.g_powers, T::g1());
    witness = T::g1_add(&witness, &commit_poly::<T>(&psi_hat, &pk.h_powers, pk.h1));

    
    return (i, phi_i, phi_hat_i, witness);
}


fn queryzk<T: Curve>(pk: &Pk<T>, set: &HashSet<T::Scalar>, phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, kj: T::Scalar)
-> (T::Scalar, T::G1, Option<T::Scalar>, Option<(T::G1, T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>) {

    let (kj, phi_kj, phi_hat_kj, witness) = create_witness(phi, phi_hat, kj, pk);
    

    if set.contains(&kj) {
        return (kj, witness, Some(phi_hat_kj), None);
    };

    let p1 = T::g1_mul(&phi_kj, &T::g1());
    let p2 = T::g1_mul(&phi_hat_kj, &pk.h1);

    let (n1, n2, s1, s2) = fiat_shamir_proof(pk, phi_kj, phi_hat_kj);

    return (kj, witness, None, Some((p1, p2, n1, n2, s1, s2)))    
}



fn verifyzk<T: Curve>(pk: &Pk<T>, commitment: T::G1, pi_sj: Option<(T::G1, T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>, kj: T::Scalar, witness: T::G1, phi_hat_kj: Option<T::Scalar>) -> bool {

    if phi_hat_kj.is_some() {
        let phi_hat_kj= phi_hat_kj.expect("invalid state");
        println!("kj is in the set");
        return verifyeval(pk, commitment, kj, T::scalar_from_literal(&0), phi_hat_kj, witness);
    }
    // always revealing phi_hat_kj allows us to use the verifyeval function above, such that the commiter cannot deny kj is in the set


    if pi_sj.is_none() {
        return false
    } 

    

    let zero = T::g1_mul(&T::scalar_from_literal(&0), &T::g1());

    let (p1, p2, n1, n2, s1, s2) = pi_sj.expect("invalid state");

    // commiter lied phi(kj) == 0
    if p1 == zero {
        println!("commiter lied");
        return false
    }

    
    let c = T::fiat_shamir_hash(p1, p2, n1, n2, pk.h1);
    
    // we require both proofs to be valid
    if !fiat_shamir_verify::<T>(p1, T::g1(), n1, s1, c) || !fiat_shamir_verify::<T>(p2, pk.h1, n2, s2, c) {
       return false 
    }
    println!("fiat shamir is valid");

    let proof = T::g1_add(&p1, &p2);
    

    let left = T::pairing(&witness, &T::g2_sub(&pk.alpha_g2, &T::g2_mul(&kj, &T::g2())));
    let right = T::pairing(&T::g1_sub(&commitment, &proof), &T::g2());
    
    left == right    
}



fn verifyeval<T: Curve>(pk: &Pk<T>, commitment: T::G1, kj: T::Scalar, phi_kj: T::Scalar, phi_hat_kj: T::Scalar, witness: T::G1) -> bool {
    
    let left = T::pairing(&witness, &T::g2_sub(&pk.alpha_g2, &T::g2_mul(&kj, &T::g2())));

    let ys = T::g1_add(&T::g1_mul(&phi_kj, &T::g1()), &T::g1_mul(&phi_hat_kj, &pk.h1));

    let right = T::pairing(&T::g1_sub(&commitment, &ys), &T::g2());
    
    left == right
}

fn fiat_shamir_proof<T: Curve>(pk: &Pk<T>, a: T::Scalar, b: T::Scalar) -> (T::G1, T::G1, T::Scalar, T::Scalar) {
    let mut rng = rand::rng();
    let r1 = rng.random();
    let r2 = rng.random();

    let r1 = T::scalar_from_literal(&r1); 
    let r2 = T::scalar_from_literal(&r2); 

    let n1 = T::g1_mul(&r1, &T::g1());
    let n2 = T::g1_mul(&r2, &pk.h1);
    
    let z1 = T::g1_mul(&a, &T::g1());
    let z2 = T::g1_mul(&b, &pk.h1);

    let c = T::fiat_shamir_hash(z1, z2, n1, n2, pk.h1);

    let s1 = r1 + c * a; 
    let s2 = r2 + c * b; 

    (n1, n2, s1, s2)
}

fn fiat_shamir_verify<T: Curve>(z: T::G1, gen: T::G1, nonce: T::G1, s: T::Scalar, c: T::Scalar) -> bool {

    let left  = T::g1_mul(&s, &gen);
    let right = T::g1_add(&nonce, &T::g1_mul(&c, &z));

    left == right
}


#[cfg(test)]
mod tests {
    use quickcheck::{QuickCheck, Gen, Arbitrary};
    use quickcheck_macros::quickcheck;
    use hacspec_bls12_381::*;
    use super::*;
    use curve::SpecCurve;
    

    #[derive(Debug, Clone)]
    struct ConstrainedPoly(Vec<u128>);

    impl Arbitrary for ConstrainedPoly {
        fn arbitrary(g: &mut Gen) -> Self {
            // Length between 3 and 13 inclusive
            let size = u8::arbitrary(g);
            
            let size = (size % 10 + 3) as usize;
            
            let mut vec = Vec::with_capacity(size);
            
            for _ in 1..size {
                // Coefficient between 1 and 10 inclusive
                let val = u128::arbitrary(g);
                vec.push(val);
            }
            
            ConstrainedPoly(vec)
        }
    }
    
    #[test] 
    fn test_kzg_commitment() {
        // Define custom generators similar to your existing code
        fn prop(poly: ConstrainedPoly, kj: u128) -> bool {
            use curve::SpecCurve as Curve;

            let kj = Curve::scalar_from_literal(&kj);
            
            let poly = poly.0;

            // let kj = poly[poly.len() - 2]; 

            let degree = poly.len() + 2;
            

            println!("degree: {degree}");
            let pk: Pk<SpecCurve> = setup(degree as u128);
            
            println!("created trusted setup");
            

            let mut set = HashSet::new();

            for i in poly {
                set.insert(Curve::scalar_from_literal(&i)); 
            }

            let (commitment, phi, phi_hat) = commitzk(&pk, &set);
            
            println!("{:?}", phi);
            println!("commited");

            let (kj, witness, phi_hat_kj, pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, kj);
            println!("queried");
            



            let result = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
            println!("verified: {result}");
            

            return result
        

        }

        // Run exactly 5 tests with constrained inputs
        QuickCheck::new()
            .tests(1)
            .quickcheck(prop as fn(ConstrainedPoly, u128) -> bool);
    }
    
    #[quickcheck]
    fn test_fiat_verification(a: u128, b: u128, lambda: u128) -> bool {
        
        
        let pk: Pk<SpecCurve> = setup(1);

        
        let a = Scalar::from_literal(a);
        let b = Scalar::from_literal(b);
            
        let p1 = g1mul(a, SpecCurve::g1());
        let p2 = g1mul(b, pk.h1);

            
        let (n1, n2, s1, s2) = fiat_shamir_proof(&pk, a, b);
        

        let c = SpecCurve::fiat_shamir_hash(p1, p2, n1, n2, pk.h1);

        
        return fiat_shamir_verify::<SpecCurve>(p1, SpecCurve::g1(), n1, s1, c) && fiat_shamir_verify::<SpecCurve>(p2, pk.h1, n2, s2, c);
    }


    #[quickcheck]
    fn test_fiat_forgery(a: u128, b: u128) -> bool {

    let pk: Pk<curve::SpecCurve> = setup(1);

    let a = Scalar::from_literal(a);
    let b = Scalar::from_literal(b);
        
    let p1 = g1mul(a, SpecCurve::g1());
    let p2 = g1mul(b, pk.h1);
    

    // fake knowledge of a by simulating guessing it
    let mut rng = rand::rng();
    let a = Scalar::from_literal(rng.random());


        
    let (n1, n2, s1, s2) = fiat_shamir_proof(&pk, a, b);
    

    let c = SpecCurve::fiat_shamir_hash(p1, p2, n1, n2, pk.h1);

    
    let res1 = fiat_shamir_verify::<SpecCurve>(p1, SpecCurve::g1(), n1, s1, c);
    let res2 = fiat_shamir_verify::<SpecCurve>(p2, pk.h1, n2, s2, c);
    

    return  !res1 || !res2;
    }
    

    #[quickcheck] 
    fn test_kzg_commitment_fast(poly: ConstrainedPoly, kj: u128) -> bool {
            use curve::FastCurve as Curve;

            let kj = Curve::scalar_from_literal(&kj);
            
            let poly = poly.0;

            let degree = poly.len() + 2;
            

            println!("degree: {degree}");
            let pk: Pk<Curve> = setup(degree as u128);
            
            println!("created trusted setup");
            

            let mut set = HashSet::new();

            for i in poly {
                set.insert(Curve::scalar_from_literal(&i)); 
            }

            let (commitment, phi, phi_hat) = commitzk(&pk, &set);
            
            println!("{:?}", phi);
            println!("commited");

            let (kj, witness, phi_hat_kj, pi_sj) = queryzk(&pk, &set, &phi, &phi_hat, kj);
            println!("queried");
            



            let result = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
            println!("verified: {result}");
            

            return result
        

        }

}