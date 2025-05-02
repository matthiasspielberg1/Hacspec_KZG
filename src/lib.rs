#![allow(unused_variables)]
use hacspec_bls12_381::*;
use hacspec_sha256::{hash, Sha256Digest};
use hacspec_lib::*;
use std::collections::BTreeSet;
use rand::Rng;



fn g1() -> G1 {
    (Fp::from_hex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
     Fp::from_hex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), false)
}

// // DONT ASK WHERE THIS GENERATOR COMES FROM (chatgpt)
// fn h1() -> G1 {
//     (Fp::from_hex("17d502fa43bd6a4cad2859049a0c3ecefd60240d129be65da271a4c03a9c38fa78163b9d2a919d2beb57df7d609b4919"),
//     Fp::from_hex("109019902ae93a8732abecf2ff7fecd2e4e305eb91f41c9c3267f16b6c19de138c7272947f25512745da6c466cdfd1ac"), false)
// }
// 

fn h1() -> G1 {
    g1mul(Scalar::from_literal(2489), g1())
}

fn g2() -> G2 {
    ((Fp::from_hex("24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
      Fp::from_hex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")),
     (Fp::from_hex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
      Fp::from_hex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")), false)
}

fn g1sub (p: G1, q: G1) -> G1 {
    g1add(p, g1neg(q))
}

fn g2sub (p: G2, q: G2) -> G2 {
    g2add(p, g2neg(q))
}


// applies the polynomial to input x
fn apply(polynomium: &Vec<Scalar>, x: &Scalar) -> Scalar {
    let mut result: Scalar = Scalar::from_literal(0);

    for i in 0..polynomium.len() {
        let term = polynomium[polynomium.len()-1-i] * x.pow(i as u128);
        result = result + term;
    }

    result
}



struct Pk {
    g1: Vec<G1>,
    h1: Vec<G1>,
    tau_g2: G2
}


// multiply two polynomials
pub fn multiply(f: &Vec<Scalar>, g: &Vec<Scalar>) -> Vec<Scalar> {
    let mut result = vec![Scalar::from_literal(0);f.len() + g.len() - 1];

    for (i, x) in f.iter().enumerate() {
        for (j, y) in g.iter().enumerate() {
            let current = result[i + j];
            result[i + j] = current + x.clone() * y.clone();
        }
    } 
    result
}


fn setup(degree: &u32, tau: Scalar) -> Pk {
    let mut setup_g1: Vec<G1> = Vec::new();
    let mut setup_g2: Vec<G1> = Vec::new();

    for i in 0..degree+1 {
        let power: u128 = (degree - i).into();
        let tau_power = tau.pow(power);

        setup_g1.push(g1mul(tau_power, g1()));
        setup_g2.push(g1mul(tau_power, h1()));
    };
    
    let tau_g2 = g2mul(tau, g2());
    
    return Pk{g1 : setup_g1, h1 :setup_g2, tau_g2};
}



fn commit_poly(polynomium: &Vec<Scalar> , pk: &Vec<G1>, generator: G1) -> G1 {

    // commit to the original polynomial
    let mut commitment = g1mul(Scalar::from_literal(0), generator);
    
    for i in 0..polynomium.len() { 
        let power_index = pk.len() - polynomium.len() + i;
        
        let tau_times_coefficient = g1mul(polynomium[i], pk[power_index]);
        commitment = g1add(commitment, tau_times_coefficient);
    };
    commitment
}


// commit to the set
fn commit(set: &BTreeSet<Scalar>, pk: &Pk) -> (G1, Vec<Scalar>, Vec<Scalar>) {
    let mut polynomium = vec![Scalar::from_literal(1)];
    
    let zero = Scalar::from_literal(0);

    for i in set {
        let mul = vec![Scalar::from_literal(1),  zero - *i ];
        polynomium = multiply(&polynomium, &mul);
    }

    // TODO maybe increase the hiding polynomial size
    let mut hiding_poly = vec![Scalar::from_literal(0); polynomium.len()];
    
    let mut rng = rand::rng();
    
    // create a random hiding polynomial
    for i in 0..hiding_poly.len() {
        hiding_poly[i] = Scalar::from_literal(rng.random());
    }

    
    let commitment = commit_poly(&polynomium, &pk.g1, g1());
    let hiding_commitment = commit_poly(&hiding_poly, &pk.h1, h1());

    
    (g1add(commitment,hiding_commitment), polynomium, hiding_poly)
}


// opens the commitment
// evaluates p(x_0) = y_0
// and pi = q(tau) G1
fn create_witness(polynomium: &Vec<Scalar>, hiding_poly: &Vec<Scalar>, x: Scalar, pk: &Pk) -> (Scalar, Scalar, Scalar, G1) {

    let y = apply(&polynomium, &x);
    let y_hiding = apply(&hiding_poly, &x);



    let mut r: Vec<Scalar> = polynomium.clone();
    if !r.is_empty() {
        let last_index = r.len() - 1;
        r[last_index] = r[last_index] - y;
    }

    let q = synthetic_division(&r, x);
    
    let mut witness = commit_poly(&q, &pk.g1, g1());


    let mut r: Vec<Scalar> = hiding_poly.clone();
    if !r.is_empty() {
        let last_index = r.len() - 1;
        r[last_index] = r[last_index] - y_hiding;
    }

    let q = synthetic_division(&r, x);
        
    witness = g1add(witness, commit_poly(&q, &pk.h1, h1()));


    println!("p({x}) = {:?}", y);
    println!("pi = {:?}", witness);
    
    return (x, y, y_hiding, witness);
}


fn query(set: &BTreeSet<Scalar>, polynomium: &Vec<Scalar>, hiding_poly: &Vec<Scalar>, x: Scalar, pk: &Pk) -> (Scalar, G1, Scalar, Option<Scalar>, Option<(G1, G1, G1, G1, Scalar, Scalar)>) {
    

    let (x, y, y_hiding, witness) = create_witness(polynomium, hiding_poly, x, pk);
    

    if set.contains(&x) {
        return (x, witness, y, Some(y_hiding), None);
    };
    
    let p1 = g1mul(y, g1());
    let p2 = g1mul(y_hiding, h1());

    let (n1, n2, s1, s2) = fiat_shamir_proof(y, y_hiding);

    return (x, witness, y, None, Some((p1, p2, n1, n2, s1, s2)))    
}


// divides the polynomial by (x - x_0)
fn synthetic_division(r: &Vec<Scalar>, request: Scalar) -> Vec<Scalar> {
    let mut q: Vec<Scalar> = Vec::new();
    q.push(r[0]);

    // Making synthetic division
    for i in 0..r.len()-1 {
        let next_term = q[i]*request+r[i+1];
        q.push(next_term);
    }
    
    println!("q(x)={:?}",  q);
    println!("r(x)={:?}",  r);

    if q[q.len()-1] == Scalar::from_literal(0) {
        q.pop();
    } else {
        panic!("wrong division");
    }
    
    q
}

fn verifyzk(pk: &Pk, commitment: G1, x: Scalar, witness: G1, y: Scalar, y_hiding: Option<Scalar>, proof: Option<(G1, G1, G1, G1, Scalar, Scalar)>) -> bool {
    if y_hiding.is_some() {
        let y_hiding = y_hiding.expect("invalid state");
        return verifyeval(pk, commitment, x, y, y_hiding, witness);
    } 
    
    if proof.is_none() {
        return false
    }
    
    let (p1, p2, n1, n2, s1, s2) = proof.expect("invalid state");
    

    let proof = g1add(p1, p2);

    let left = pairing(g1sub(commitment, proof), g2());
    let right = pairing(witness, g2sub(pk.tau_g2.clone(), g2mul(x, g2())));
    
    if left != right {
        return false
    } 
    
    
    let c = fiat_shamir_hash(p1, p2, n1, n2);
    
    if ! fiat_shamir_verify(p1, g1(), n1, s1, c) {
        return false
    }

    if ! fiat_shamir_verify(p2, h1(), n2, s2, c) {
        return false
    }
    
    return true;
}


fn verifyeval(pk: &Pk, commitment: G1, x: Scalar, y: Scalar, y_hiding: Scalar, witness: G1) -> bool {
    

    let left = pairing(witness, g2sub(pk.tau_g2.clone(), g2mul(x, g2())));

    let ys = g1add(g1mul(y, g1()), g1mul(y_hiding, h1()));


    let right = pairing(g1sub(commitment, ys), g2());
    
    left == right
}

fn g1_to_byte_seq(g: G1) -> ByteSeq {
    let (x, y, inf) = g;
    let x_bytes = x.to_byte_seq_be();  
    let mut result= x_bytes.concat(&y.to_byte_seq_be());
    
    let mut inf_bytes = U8::zero();
    
    if inf {
        inf_bytes = U8::one();
    }
    
    result.push(&inf_bytes);

    result
}

fn fiat_shamir_hash(z1: G1, z2: G1, n1: G1, n2: G1) -> Scalar {
    let g = g1_to_byte_seq(g1());
    let h = g1_to_byte_seq(h1());
    let z1 = g1_to_byte_seq(z1);
    let z2 = g1_to_byte_seq(z2);
    let n1 = g1_to_byte_seq(n1);
    let n2 = g1_to_byte_seq(n2);

    let bytes = g.concat(&h).concat(&z1).concat(&z2).concat(&n1).concat(&n2);
    
    let digest = hash(&bytes);

    Scalar::from_byte_seq_be(&digest)
}

fn fiat_shamir_proof(a: Scalar, b: Scalar) -> (G1, G1, Scalar, Scalar) {
    let mut rng = rand::rng();
    let r1 = rng.random();
    let r2 = rng.random();

    let r1 = Scalar::from_literal(r1); 
    let r2 = Scalar::from_literal(r2); 

    let n1 = g1mul(r1, g1());
    let n2 = g1mul(r2, h1());
    
    let z1 = g1mul(a, g1());
    let z2 = g1mul(b, h1());

    let c = fiat_shamir_hash(z1, z2, n1, n2);

    let s1 = r1 + c * a; 
    let s2 = r2 + c * b; 

    (n1, n2, s1, s2)
}

fn fiat_shamir_verify(z: G1, gen: G1, nonce: G1, s: Scalar, c: Scalar) -> bool {

    let left  = g1mul(s, gen);
    let right = g1add(nonce, g1mul(c, z));

    left == right
}


#[cfg(test)]
mod tests {
    use quickcheck::{QuickCheck, Gen, Arbitrary};
    use hacspec_bls12_381::*;
    use super::*;
    
    // Define custom generators similar to your existing code
    #[derive(Debug, Clone)]
    struct ConstrainedTau(Scalar);

    impl Arbitrary for ConstrainedTau {
        fn arbitrary(g: &mut Gen) -> Self {
            // Value between 1 and 100 inclusive
            let val = (u128::arbitrary(g));
            let tau_scalar = Scalar::from_literal(val);
            ConstrainedTau(tau_scalar)
        }
    }

    #[derive(Debug, Clone)]
    struct ConstrainedRequest(Scalar);

    impl Arbitrary for ConstrainedRequest {
        fn arbitrary(g: &mut Gen) -> Self {
            // Value between 1 and 100 inclusive
            let val = (u128::arbitrary(g));
            let val_scalar = Scalar::from_literal(val);
            ConstrainedRequest(val_scalar)
        }
    }

    #[derive(Debug, Clone)]
    struct ConstrainedPoly(Vec<Scalar>);

    impl Arbitrary for ConstrainedPoly {
        fn arbitrary(g: &mut Gen) -> Self {
            // Length between 3 and 5 inclusive
            let sizes = [10];
            let size = *g.choose(&sizes).unwrap();
            
            let mut vec = Vec::with_capacity(size);
            
            for _ in 0..size {
                // Coefficient between 1 and 10 inclusive
                let val = (u128::arbitrary(g));
                let val_scalar = Scalar::from_literal(val);
                vec.push(val_scalar);
            }
            
            ConstrainedPoly(vec)
        }
    }


    
    #[test] 
    fn test_kzg_commitment() {
        // Define custom generators similar to your existing code
        fn prop(poly: ConstrainedPoly, tau: ConstrainedTau, request: ConstrainedRequest) -> bool {
            let tau = tau.0;
            let x = request.0;
            let poly = poly.0;
            
            let mut set = BTreeSet::new();

            for i in poly {
                set.insert(i); 
            }
            
            let degree = 10;

            // Your test implementation
            let pk = setup(&degree, tau);
            
            println!("created trusted setup");

            // let mut set = BTreeSet::new();
            
            // set.insert(Scalar::from_literal(2));


            let (commitment, polynomium, hiding_poly) = commit(&set, &pk);
            
            println!("{:?}", polynomium);
            println!("commited");

            // let x = Scalar::from_literal(4);



            let (x, witness, y, y_hiding, proof) = query(&set, &polynomium, &hiding_poly, x, &pk);
            println!("queried");
            



            let result = verifyzk(&pk, commitment, x, witness, y, y_hiding, proof);
            println!("verified");
            

            return result
        

        }

        // Run exactly 5 tests with constrained inputs
        QuickCheck::new()
            .tests(1)
            .quickcheck(prop as fn(ConstrainedPoly, ConstrainedTau, ConstrainedRequest) -> bool);
    }
    
    #[test]
    fn test_fiat() {
    // let witness = (
    //     Fp::from_hex("1115ed4918b7f54aed1219c00b22aa47993d78bbadc3bb744aa822c35791d2642940e2b8a9b81727643f1f4be632f4d7"), 
    //     Fp::from_hex("d0bff703fb881e3f8747fda692d0ef009499c0af1e117dec6f2f6967c3234175ddee3863dd9c38479f6d0b2b84d5eb2"), 
    //     false);
    
    // let commitment = (
    //     Fp::from_hex("18902ab587bf439883fa83b8027c060309916e01ea21df60db35963122bd0df4194ab6d173823919e6073f44c69a8240"), 
    //     Fp::from_hex("67257dcc7b5cf2ca5fdeb4c7a5a3b5d4e8bd1af806c2e2e34a8aaee75e3b12db332ae565bd13a0a26a48ec981e43f21"), 
    //     false);

    // let proof = (
    //     Fp::from_hex("faad3b135a8f332e84292ba87d27d70b30e94bd71555884104e1caa825a685b745e00d5d919f4804db4a7da9715ef72"), 
    //     Fp::from_hex("c0d51d1130f42280eb7f78a5e0e0291f9ff698484e96f4c085b06743dae837c2720fc7c5315b09029d9adf684635922"),
    //     false);
    

    let a = Scalar::from_literal(200);
    let b = Scalar::from_literal(200);
    

    let p1= g1mul(a, g1());
    let p2= g1mul(b, h1());

    

    let mut rng = rand::rng();
    let r1 = rng.random();
    let r2 = rng.random();

    let r1 = Scalar::from_literal(r1); 
    let r2 = Scalar::from_literal(r2); 

    let n1= g1mul(r1, g1());
    let n2= g1mul(r2, h1());

    let c = fiat_shamir_hash(p1, p2, n1, n2);

    let s1 = r1 + c * a; 
    let s2 = r2 + c * b; 

    // prover outputs proof = (nonnce, s1, s2)
    
    
    // verify the proof
    let c = fiat_shamir_hash(p1, p2, n1, n2);
    

    }
}

