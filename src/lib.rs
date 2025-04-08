#![allow(unused_variables)]
use hacspec_bls12_381::*;
use hacspec_lib::*;


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

fn g1sub (p: G1, q: G1) -> G1 {
    g1add(p, g1neg(q))
}

fn g2sub (p: G2, q: G2) -> G2 {
    g2add(p, g2neg(q))
}



fn setup(degree: &u32, tau: Scalar) -> (Vec<G1>, Vec<G2>) {
    let mut setup_g1: Vec<G1> = Vec::new();
    let mut setup_g2: Vec<G2> = Vec::new();

    for i in 0..degree+1 {
        let power: u128 = (degree - i).into();
        let tau_power = tau.pow(power);

        setup_g1.push(g1mul(tau_power, g1()));
        setup_g2.push(g2mul(tau_power, g2()));
    };
    
    return (setup_g1, setup_g2);
}


// commit to the polynomial
fn commit(polynomium: &Vec<Scalar>, setup: &Vec<G1>) -> G1 {
    let mut commitment = g1mul(Scalar::from_literal(0), g1());

    for i in 0..polynomium.len() { 
        let power_index = setup.len() - polynomium.len() + i;
        
        let tau_times_coefficient = g1mul(polynomium[i], setup[power_index]);
        commitment = g1add(commitment, tau_times_coefficient);
    };

    println!("commitment: {:?}", commitment);
    commitment
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


// opens the commitment
// evaluates p(x_0) = y_0
// and pi = q(tau) G1
fn open(polynomium: &Vec<Scalar>, x: &Scalar, setup: &Vec<G1>) -> (Scalar, G1) {
    let mut r: Vec<Scalar> = polynomium.clone();

    let y = apply(&polynomium, x);

    if !r.is_empty() {
        let last_index = r.len() - 1;
        r[last_index] = r[last_index] - y;
    }

    let q = synthetic_division(&r, *x);
    
    let pi = commit(&q, setup);
    
    println!("p({x}) = {:?}", y);
    println!("pi = {:?}", pi);
    
    return (y, pi);
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
    

    if q[q.len()-1] == Scalar::from_literal(0) {
        q.pop();
    } else {
        panic!("wrong division");
    }
    

    println!("q(x)={:?}",  q);
    println!("r(x)={:?}",  r);

    q
}

fn verify(pi: G1, x: Scalar, y: Scalar, commitment: G1, tau_g2: G2) -> bool {
    let left = pairing(pi, g2sub(tau_g2, g2mul(x, g2())));
    
    println!("left: {:?}", left);
    let right = pairing(g1sub(commitment, g1mul(y, g1())), g2());

    println!("right : {:?}", right);
    
    

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
        fn prop(tau: ConstrainedTau, poly: ConstrainedPoly, request: ConstrainedRequest) -> bool {
            let tau = tau.0;
            let request = request.0;
            let poly = poly.0.clone();

            // Your test implementation
            let (setup_g1, setup_g2) = setup(&(poly.len() as u32), tau);


            let commitment = commit(&poly, &setup_g1);

            let (y, pi) = open(&poly, &request, &setup_g1);


            // we want to find tau^1 g2, which is in the second last index
            // since these vectors are indexes from biggest to smallest
            let tau_g2 = setup_g2[setup_g2.len() - 2]; 

            verify(pi, request, y, commitment, tau_g2) 
        }

        // Run exactly 5 tests with constrained inputs
        QuickCheck::new()
            .tests(1)
            .quickcheck(prop as fn(ConstrainedTau, ConstrainedPoly, ConstrainedRequest) -> bool);
    }
}
