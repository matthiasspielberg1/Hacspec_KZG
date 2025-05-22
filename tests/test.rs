use std::time::{Duration, Instant};
use std::collections::HashSet;
use kzg::*;
use curve::*;
use rand::random;


struct Timer(Vec<Duration>, Vec<Duration>, Vec<Duration>, Vec<Duration>);        

// generates n random u128
// lets us avoid generating randomness directly in our kzg implementation
fn generate_randomness(n: usize) -> Vec<u128> {
    let mut rand: Vec<u128> = Vec::with_capacity(n); 

    for _ in 0..n {
        rand.push(random())
}
rand
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
    
    println!("total time: {}ms", total);
    println!("total time without setup: {}ms", total - setup_time);
    
    println!("\n");
}

fn benchmark_single_iteration<T: Curve>(poly: &Vec<u128>, times: &mut Timer) {
    let degree = poly.len() + 2; 
    let mut random = generate_randomness(poly.len() + 6);
     
    let kj_literal = random.pop().expect("not enough randomness provided"); 

    let mut timer = Instant::now();
    let pk = kzg::setup::<T>(degree as u128, &mut random);
    times.0.push(timer.elapsed());

    let mut set = HashSet::new();
    for i in poly.iter() {
        set.insert(T::scalar_from_literal(i)); 
    }
    
    timer = Instant::now();
    let (commitment, phi, phi_hat) = kzg::commitzk(&pk, &set, &mut random);
    times.1.push(timer.elapsed());

    let kj = T::scalar_from_literal(&kj_literal); 

    timer = Instant::now();
    let (kj, witness, phi_hat_kj, pi_sj) = kzg::queryzk(&pk, &set, &phi, &phi_hat, kj, &mut random); 
    times.2.push(timer.elapsed());
    
    timer = Instant::now();
    kzg::verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);
    times.3.push(timer.elapsed());    
}


#[test]
fn benchmark() {   
    println!(); 
    for i in [5, 10, 20, 50, 400] {
        let poly = generate_randomness(i.clone());
            
        let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for _ in 0..20 {
            benchmark_single_iteration::<FastCurve>(&poly, &mut timer);
        }
        print_timer("fast", i, 20, timer);
    }     
    
    println!("\n");
    for i in [5] {
        let poly = generate_randomness(i.clone());
        let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for _ in 0..5 {
            benchmark_single_iteration::<SpecCurve>(&poly, &mut timer);
        }
        print_timer("specification", i, 5, timer);
    }     
}

#[test]
fn profile_blstrs() {
    // this value is discarded
    let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    
    let degree = 10000;
    let poly = generate_randomness(degree);
    benchmark_single_iteration::<FastCurve>(&poly.clone(), &mut timer);
    print_timer("blstrs", degree, 1, timer)
}

#[test]
fn profile_spec() {
    // this value is discarded
    let mut timer = Timer(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    
    let poly = generate_randomness(30);
    benchmark_single_iteration::<SpecCurve>(&poly.clone(), &mut timer);
}