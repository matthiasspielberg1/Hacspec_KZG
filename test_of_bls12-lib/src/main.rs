#![allow(unused_variables)]
use hacspec_bls12_381::*;
use hacspec_lib::*;

fn main() {

    let fp1 = Fp::from_literal(2);
    let fp2 = Fp::from_literal(3);

    let scalar = Scalar::from_signed_literal(-2);

    println!("{:?}", scalar);

    println!("{:?}", fp2add((fp1, fp1), fp2neg((fp2, fp2))));


    return;


    println!("\n========== KZG PROTOCOL DEBUG OUTPUT ==========");

    let g1_base_point: G1 = g1();
    let g2_base_point: G2 = g2();
    println!("G1 base point: {:?}", g1_base_point);
    println!("G2 base point: {:?}", g2_base_point);
    
    let tau = 0xf;
    println!("\nCreating Tau: {}", tau);

    let degree = 2;
    println!("\nDegree of polynomium is: {}", degree);

    let setup = create_trusted_setup(&degree, tau);
    println!("\nTrusted setup has been created, powers of tau are:\n\n {:?}", setup.0);
    println!("\nTau in G2: {:?}", setup.2);

    let p: Vec<i128> = Vec::from([2, 1, 1]);
    println!("\nPolynomial P(x) = {:?} (represents 2x² + x +     1)", p);

    let commitment = create_commitment(&p, &setup);
    println!("\nCommitment is:\n {:?}", commitment);
    println!("\nFinished setup and commitment");

    let request = 2;
    println!("\nEvaluation point x₀ = {}", request);

    let true_value: i128 = calc_request(&p, &request);
    println!("True value P({}) = {}", request, true_value);
    
    // Debug: check if P(x₀) calculation is correct
    println!("\nVerifying P(x₀) calculation:");
    println!("Manual calculation of P(4):");
    println!("2(2²) + 1(2) + 1 = 2(4) + 2 + 1 = 8 + 4 + 1 = 11");
    println!("Calculated value: {}", true_value);

    let r = calc_r(&p, &true_value);
    println!("\nThis is R(x): {:?}", r);
    
    // Debug: verify R(x₀) = 0
    let r_at_x0 = calc_request(&r, &request);
    println!("\nVerifying R(x₀) = 0:");
    println!("R({}) = {}", request, r_at_x0);
    if r_at_x0 == 0 {
        println!("R(x₀) = 0 ✓ (correct)");
    } else {
        println!("R(x₀) ≠ 0 ✗ (error!)");
    }

    let q = calc_q(&r, &request);
    println!("This is Q(x): {:?}", q);
    
    // Debug: verify Q(x) * (x - x₀) = R(x)
    println!("\nVerifying Q(x) * (x - x₀) = R(x):");
    
    // Check at a different point
    let test_point = 5;
    let q_at_test = calc_request(&q, &test_point);
    let r_at_test = calc_request(&r, &test_point);
    let expected = q_at_test * (test_point - request);
    
    println!("At x = {}:", test_point);
    println!("Q({}) = {}", test_point, q_at_test);
    println!("(x - x₀) = ({} - {}) = {}", test_point, request, test_point - request);
    println!("Q(x) * (x - x₀) = {} * {} = {}", q_at_test, test_point - request, expected);
    println!("R({}) = {}", test_point, r_at_test);
    
    if expected == r_at_test {
        println!("Q(x) * (x - x₀) = R(x) ✓ (correct)");
    } else {
        println!("Q(x) * (x - x₀) ≠ R(x) ✗ (error!)");
    }

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

    println!("Request used is: {}", request);
    
    let x0_g2 = g2mul(Scalar::from_signed_literal(request), g2_base_point);
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
    let y0_point = g1mul(Scalar::from_signed_literal(true_value), g1_base_point);
    println!("[y₀]₁: {:?}", y0_point);
    
    println!("\nCalculating C - [y₀]₁...");
    let commitment_minus_y0 = g1sub(commitment, y0_point);
    println!("C - [y₀]₁: {:?}", commitment_minus_y0);

    println!("\nCalculating Rightside e(C - [y₀]₁, [1]₂)...");
    let rightside = pairing(g1sub(commitment, g1mul(Scalar::from_signed_literal(true_value), g1_base_point)), g2_base_point);
    println!("rightside: {:?}", rightside);
    println!("Rightside has been calculated!");

    println!("\n========== VERIFICATION RESULT ==========");
    println!("Checking if left and right are equal: {}", leftside == rightside);
    if leftside == rightside {
        println!("✓ VERIFICATION SUCCESSFUL");
    } else {
        println!("✗ VERIFICATION FAILED");
    }


    let lhs_1 = g1mul(Scalar::from_signed_literal(q[0]), powers_of_tau_g1[1]);
    let rhs_1 = g1sub(commitment, g1mul(Scalar::from_signed_literal(true_value), g1_base_point));

    // Check if they're equal directly (they shouldn't be, but this helps debug)
    println!("Direct equality check: {}", lhs_1 == rhs_1);

    // Try the equation in reverse
    let lhs_2 = pairing(g1_base_point, g2mul(Scalar::from_signed_literal(q[0]), g2sub(tau_g2, x0_g2)));
    let rhs_2 = pairing(g1sub(commitment, g1mul(Scalar::from_signed_literal(true_value), g1_base_point)), g2_base_point);

    println!("Alternative equation check: {}", lhs_2 == rhs_2);

    println!("\n========== BILINEARITY TEST ==========");
    test_pairing_bilinearity();



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


fn create_trusted_setup (degree: &u8, tau: u128) -> (Vec<G1>, G2, G2) {
    println!("Creating trusted setup...");
    let g1_base_point: G1 = g1();
    let g2_base_point: G2 = g2();

    let mut powers_of_tau: Vec<G1> = Vec::new();
    println!("Generating powers of tau in G1:");

    for i in 0..degree+1 {
        let power = degree - i;
        let tau_power = tau.pow(power.into());
        println!("  Power {}: τ^{} = {}", i, power, tau_power);
        powers_of_tau.push(g1mul(Scalar::from_literal(tau_power), g1_base_point));
    };

    println!("Generating [τ]₂...");
    let tau_g2 = g2mul(Scalar::from_literal(tau), g2_base_point);

    (powers_of_tau, g2_base_point, tau_g2)
}


fn create_commitment (polynomium: &Vec<i128>, setup: &(Vec<G1>, G2, G2)) -> G1 {
    println!("Creating commitment C = [P(τ)]₁...");
    let powers_of_tau_g1 = &setup.0;
    let mut commitment = G1::default();
    println!("Initial commitment set to identity");

    for i in 0..polynomium.len() {
        println!("Adding term {}: coefficient {} × [τ^{}]₁", 
                 i, polynomium[i], polynomium.len() - 1 - i);
        let tau_times_coefficient = g1mul(Scalar::from_signed_literal(polynomium[i]), powers_of_tau_g1[i]);
        commitment = g1add(commitment, tau_times_coefficient);
    };

    println!("Commitment calculation complete");
    commitment
}

fn calc_request (polynomium: &Vec<i128>, request: &i128) -> i128 {
    println!("Evaluating polynomial {:?} at x = {}", polynomium, request);
    let mut result: i128 = 0;

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

fn calc_r (polynomium: &Vec<i128>, true_value: &i128) -> Vec<i128> {
    println!("Calculating R(x) = P(x) - P(x₀)...");
    let mut r: Vec<i128> = Vec::new();

    for i in 0..polynomium.len() {
        r.push(polynomium[i].try_into().unwrap());
        println!("Copied coefficient {}: {}", i, r[i]);
    }

    if !r.is_empty() {
        let last_index = polynomium.len() - 1;
        println!("Subtracting {} from constant term at index {}", true_value, last_index);
        r[last_index] -= true_value;
        println!("New constant term value: {}", r[last_index]);
    }

    println!("R(x) = {:?}", r);
    r
}

fn calc_q (r: &Vec<i128>, request: &i128) -> Vec<i128> {
    println!("Calculating Q(x) = R(x) / (x - x₀) using synthetic division...");
    let mut q: Vec<i128> = Vec::new();
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

    if q[r.len()-1] == 0 {
        println!("Last term is 0, removing it (remainder is 0)");
        q.pop();
    } else {
        println!("WARNING: Last term is not 0 (got {}), which means remainder is not 0!", 
                 q[r.len()-1]);
    }

    println!("Final Q(x) = {:?}", q);
    q
}

fn calc_pi(q: &Vec<i128>, setup: &(Vec<G1>, G2, G2)) -> G1 {
    println!("Calculating proof π = [Q(τ)]₁...");
    let powers_of_tau_g1 = &setup.0;
    let mut pi = G1::default();
    println!("Initial π set to identity");
    let g1_base_point = g1();
    
    for i in 0..q.len() {
        let power_index = powers_of_tau_g1.len() - q.len() + i;
        println!("Processing term {}: coefficient {} (mapping to index {})", 
                 i, q[i], power_index);
        
        let qi_scalar = Scalar::from_signed_literal(q[i]);
        let term = g1mul(qi_scalar, powers_of_tau_g1[power_index]);
        pi = g1add(pi, term);
    }
    
    println!("π calculation complete");
    pi
}

fn test_pairing_bilinearity() {
    println!("\n╔════════════════════════════════════════════╗");
    println!("║           PAIRING LIBRARY TEST             ║");
    println!("╚════════════════════════════════════════════╝\n");

    // Get base generator points
    let g1_base_point: G1 = g1();
    let g2_base_point: G2 = g2();
    
    // Create some scalar values
    let a: u128 = 3;
    let b: u128 = 5;
    
    println!("Testing pairing bilinearity property:");
    println!("e([a]₁, [b]₂) = e([1]₁, [ab]₂)");
    println!("With a = {} and b = {}\n", a, b);
    
    // Calculate [a]₁
    let a_g1 = g1mul(Scalar::from_literal(a), g1_base_point);
    println!("Calculated [a]₁");
    
    // Calculate [b]₂
    let b_g2 = g2mul(Scalar::from_literal(b), g2_base_point);
    println!("Calculated [b]₂");
    
    // Calculate [ab]₂
    let ab_g2 = g2mul(Scalar::from_literal(a * b), g2_base_point);
    println!("Calculated [ab]₂");
    
    // Compute pairings
    println!("Computing e([a]₁, [b]₂)...");
    let left = pairing(a_g1, b_g2);
    
    println!("Computing e([1]₁, [ab]₂)...");
    let right = pairing(g1_base_point, ab_g2);
    
    // Check if they're equal
    println!("\nVerification result:");
    println!("e([a]₁, [b]₂) = e([1]₁, [ab]₂): {}", left == right);
    
    // Try another property: e([a]₁, [1]₂) = e([1]₁, [a]₂)
    println!("\nTesting another property:");
    println!("e([a]₁, [1]₂) = e([1]₁, [a]₂)");
    
    let a_g2 = g2mul(Scalar::from_literal(a), g2_base_point);
    println!("Calculated [a]₂");
    
    let left2 = pairing(a_g1, g2_base_point);
    let right2 = pairing(g1_base_point, a_g2);
    
    println!("e([a]₁, [1]₂) = e([1]₁, [a]₂): {}", left2 == right2);
}