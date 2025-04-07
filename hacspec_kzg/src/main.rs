#![allow(unused_variables)]
use hacspec_bls12_381::*;
use hacspec_lib::*;

fn main() {

    println!("\n========== KZG PROTOCOL DEBUG OUTPUT ==========");

    let tau_scalar= Scalar::from_hex("16000000000000043200000");

    println!("tau_value: {:?}", tau_scalar);

    let degree = 4;

    println!("\nDegree of polynomium is: {}", degree);

    let setup = create_trusted_setup(&degree, tau_scalar);
    println!("\nTrusted setup has been created, powers of tau are:\n\n {:?}", setup.0);
    println!("\nTau in G2: {:?}", setup.2);

    let p2: Vec<Scalar> = Vec::from([
        Scalar::from_literal(2),
        Scalar::from_literal(68),
        Scalar::from_literal(390),
        Scalar::from_literal(256)
    ]);


    let commitment = create_commitment(&p2, &setup);
    println!("\nCommitment is:\n {:?}", commitment);
    println!("\nFinished setup and commitment");

    let request_scalar = Scalar::from_hex("2");

    // 15900000000000000000000000000000

    let true_value: Scalar = calc_request(&p2, &request_scalar);
    
    // Debug: check if P(x₀) calculation is correct
    println!("\nVerifying P(x₀) calculation:");
    println!("Manual calculation of P(4):");
    println!("2(2²) + 1(2) + 1 = 2(4) + 2 + 1 = 8 + 4 + 1 = 11");
    println!("Calculated value: {}", true_value);

    let r = calc_r(&p2, &true_value);
    println!("\nThis is R(x): {:?}", r);
    
    // Debug: verify R(x₀) = 0
    let r_at_x0 = calc_request(&r, &request_scalar);
    println!("\nVerifying R(x₀) = 0:");


    let q = calc_q(&r, request_scalar);
    println!("This is Q(x): {:?}", q);
    
    // Debug: verify Q(x) * (x - x₀) = R(x)
    println!("\nVerifying Q(x) * (x - x₀) = R(x):");


    println!("\nCalculating proof π = [Q(τ)]₁...");
    println!("Q(x) = {:?}", q);
    println!("Available powers of tau: {:?}", setup.0.len());
    
    let pi = calc_pi(&q, &setup);
    println!("\nThis is Pi: {:?}", pi);
    
    // Debug: detailed proof calculation
    println!("\nDetailed proof calculation:");
    let powers_of_tau_g1 = &setup.0;
    for i in 0..q.len() {
        let power_index = powers_of_tau_g1.len() - q.len() + i;
        println!("Term {}: coefficient {} uses tau^{} at index {}", 
                 i, q[i], powers_of_tau_g1.len() - 1 - power_index, power_index);
    }

    let tau_g2 = setup.2; 
    println!("\n[τ]₂: {:?}", tau_g2);

    
    let x0_g2 = g2mul(request_scalar, g2());
    println!("[x₀]₂: {:?}", x0_g2);
    
    println!("\nCalculating [τ - x₀]₂...");
    let tau_minus_x0 =  g2sub(tau_g2, x0_g2);
    println!("[τ - x₀]₂: {:?}", tau_minus_x0);

    println!("\nCalculating Leftside e(π, [τ - x₀]₂)...");
    
    // Uncomment to calculate actual KZG verification
    let leftside = pairing(pi, g2sub(tau_g2, x0_g2));
    println!("leftside: {:?}", leftside);
    println!("Leftside has been calculated!");

    println!("\nCalculating [y₀]₁...");
    let y0_point = g1mul(true_value, g1());
    println!("[y₀]₁: {:?}", y0_point);
    
    println!("\nCalculating C - [y₀]₁...");
    let commitment_minus_y0 = g1sub(commitment, y0_point);
    println!("C - [y₀]₁: {:?}", commitment_minus_y0);

    println!("\nCalculating Rightside e(C - [y₀]₁, [1]₂)...");

    let rightside = pairing(g1sub(commitment, g1mul(true_value, g1())), g2());
    println!("rightside: {:?}", rightside);
    println!("Rightside has been calculated!");

    println!("\n========== VERIFICATION RESULT ==========");
    println!("Checking if left and right are equal: {}", leftside == rightside);
    if leftside == rightside {
        println!("✓ VERIFICATION SUCCESSFUL");
    } else {
        println!("✗ VERIFICATION FAILED");
    }




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

fn g1sub (p: G1, q: G1) -> G1 {
    g1add(p, g1neg(q))
}

fn g2sub (p: G2, q: G2) -> G2 {
    g2add(p, g2neg(q))
}



fn create_trusted_setup (degree: &u32, tau: Scalar) -> (Vec<G1>, G2, G2) {
    println!("Creating trusted setup...");

    let mut powers_of_tau: Vec<G1> = Vec::new();
    println!("Generating powers of tau in G1:");

    for i in 0..degree+1 {
        let power: u128 = (degree - i).into();
        let mut tau_power_2 = Scalar::from_literal(1);

        for j in 0..(degree - i) {
            tau_power_2 = tau_power_2.wrap_mul(tau);
        }

        println!("HERE: {:?}", tau_power_2);

        let tau_power = tau.pow(power);
        println!("  Power {}: τ^{} = {}", i, power, tau_power);
        powers_of_tau.push(g1mul(tau_power_2, g1()));
    };

    println!("Generating [τ]₂...");
    let tau_g2 = g2mul(tau, g2());

    (powers_of_tau, g2(), tau_g2)
}


fn create_commitment (polynomium: &Vec<Scalar>, setup: &(Vec<G1>, G2, G2)) -> G1 {
    println!("Creating commitment C = [P(τ)]₁...");

    let powers_of_tau_g1 = &setup.0;
    let mut commitment = g1mul(Scalar::from_literal(0), g1());
    println!("Initial commitment set to identity");

    for i in 0..polynomium.len() {
        println!("Adding term {}: coefficient {} × [τ^{}]₁", 
                 i, polynomium[i], polynomium.len() - 1 - i);

                 
        let power_index = powers_of_tau_g1.len() - polynomium.len() + i;

        println!("Power of tau being calculated with: {:?}", powers_of_tau_g1[i]);
        
        let tau_times_coefficient = g1mul(polynomium[i], powers_of_tau_g1[power_index]);
        commitment = g1add(commitment, tau_times_coefficient);
    };

    println!("Commitment calculation complete");
    commitment
}

fn calc_request (polynomium: &Vec<Scalar>, request: &Scalar) -> Scalar {
    println!("Evaluating polynomial {:?} at x = {}", polynomium, request);
    let mut result: Scalar = Scalar::from_literal(0);


    for i in 0..polynomium.len() {
        let power = i.try_into().unwrap();
        let term = polynomium[polynomium.len()-1-i] * request.pow(power);
        println!("Term {}: {} × {}^{} = {}", 
                 i, polynomium[polynomium.len()-1-i], request, power, term);
        result = result + term;
    }

    println!("Evaluation result: {}", result);
    result
}

fn calc_r (polynomium: &Vec<Scalar>, true_value: &Scalar) -> Vec<Scalar> {
    println!("Calculating R(x) = P(x) - P(x₀)...");
    let mut r: Vec<Scalar> = Vec::new();

    for i in 0..polynomium.len() {
        r.push(polynomium[i]);
        println!("Copied coefficient {}: {}", i, r[i]);
    }

    if !r.is_empty() {
        let last_index = polynomium.len() - 1;
        println!("Subtracting {} from constant term at index {}", true_value, last_index);
        r[last_index] = r[last_index] - *true_value;
        println!("New constant term value: {}", r[last_index]);
    }

    println!("R(x) = {:?}", r);
    r
}

fn calc_q (r: &Vec<Scalar>, request: Scalar) -> Vec<Scalar> {
    println!("Calculating Q(x) = R(x) / (x - x₀) using synthetic division...");
    let mut q: Vec<Scalar> = Vec::new();
    q.push(r[0]);
    println!("Initial Q(x) term: {}", q[0]);

    // Making synthetic division
    for i in 0..r.len()-1 {
        let next_term = q[i]*request+r[i+1];
        println!("Next term calculation: {}×{} + {} = {}", 
                 q[i], request, r[i+1], next_term);
        q.push(next_term);
    }
    
    println!("Complete Q(x) before remainder check: {:?}", q);

    if q[r.len()-1] == Scalar::from_literal(0) {
        println!("Last term is 0, removing it (remainder is 0)");
        q.pop();
    } else {
        println!("WARNING: Last term is not 0 (got {}), which means remainder is not 0!", 
                 q[r.len()-1]);
    }

    println!("Final Q(x) = {:?}", q);
    q
}

fn calc_pi(q: &Vec<Scalar>, setup: &(Vec<G1>, G2, G2)) -> G1 {
    println!("Calculating proof π = [Q(τ)]₁...");
    let powers_of_tau_g1 = &setup.0;
    let mut pi = g1mul(Scalar::from_literal(0), g1());
    println!("Initial π set to identity");
    
    for i in 0..q.len() {
        let power_index = powers_of_tau_g1.len() - q.len() + i;
        println!("Processing term {}: coefficient {} (mapping to index {})", 
                 i, q[i], power_index);
        
        let qi_scalar = q[i];
        let term = g1mul(qi_scalar, powers_of_tau_g1[power_index]);
        pi = g1add(pi, term);
    }
    
    println!("π calculation complete");
    pi
}



#[cfg(test)]
mod tests {
    use quickcheck::{QuickCheck, Gen, Arbitrary};
    use hacspec_bls12_381::*;
    use super::*;
    
    #[test]
    fn test_KZG_commit_degree_0_limited() {
        // Define custom generators similar to your existing code
        #[derive(Debug, Clone)]
        struct ConstrainedTau(Scalar);

        impl Arbitrary for ConstrainedTau {
            fn arbitrary(g: &mut Gen) -> Self {
                // Value between 1 and 100 inclusive
                let val = (u128::arbitrary(g) % 10) + 1;
                let tau_scalar = Scalar::from_literal(val);
                let tau_scalar_hex = Scalar::from_hex("180000000000000000000000000000002");
                ConstrainedTau(tau_scalar)
            }
        }

        #[derive(Debug, Clone)]
        struct ConstrainedRequest(Scalar);

        impl Arbitrary for ConstrainedRequest {
            fn arbitrary(g: &mut Gen) -> Self {
                // Value between 1 and 100 inclusive
                let val = (u128::arbitrary(g) % 100) + 1;
                let val_scalar = Scalar::from_literal(val);
                ConstrainedRequest(val_scalar)
            }
        }

        #[derive(Debug, Clone)]
        struct ConstrainedPoly(Vec<Scalar>);

        impl Arbitrary for ConstrainedPoly {
            fn arbitrary(g: &mut Gen) -> Self {
                // Length between 3 and 5 inclusive
                let sizes = [3];
                let size = *g.choose(&sizes).unwrap();
                
                let mut vec = Vec::with_capacity(size);
                
                for _ in 0..size {
                    // Coefficient between 1 and 10 inclusive
                    let val = (u128::arbitrary(g) % 500) + 1;
                    let val_scalar = Scalar::from_literal(val);
                    vec.push(val_scalar);
                }
                
                ConstrainedPoly(vec)
            }
        }

        fn prop(tau: ConstrainedTau, poly: ConstrainedPoly, request: ConstrainedRequest) -> bool {
            let tau = tau.0;
            let request = request.0;
            let poly = poly.0.clone();
            
            println!("TESTING: tau={}, request={}, poly={:?}", tau, request, poly);
            
            // Your test implementation
            let setup = create_trusted_setup(&(poly.len() as u32), tau);

            let mut poly_scalar: Vec<Scalar> = Vec::new();
            for i in 0..poly.len() {
                poly_scalar.push(poly[i]);
            }

            let commitment = create_commitment(&(&poly_scalar), &setup);
            let value = calc_request(&poly_scalar, &(request));
            let rx = calc_r(&poly_scalar, &value);
            let qx = calc_q(&rx, (request));
            let pi = calc_pi(&qx, &setup);
            let tau_g2 = setup.2; 
            let x0_g2 = g2mul(request, g2());
            let tau_minus_x0 = g2sub(tau_g2, x0_g2);
            
            let leftside = pairing(pi, tau_minus_x0);
            let rightside = pairing(g1sub(commitment, g1mul(value, g1())), g2());
            
            let result = leftside == rightside;
            println!("RESULT: {}", result);
            
            result
        }

        // Run exactly 5 tests with constrained inputs
        QuickCheck::new()
            .tests(1)
            .quickcheck(prop as fn(ConstrainedTau, ConstrainedPoly, ConstrainedRequest) -> bool);
    }
}
