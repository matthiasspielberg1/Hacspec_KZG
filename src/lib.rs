#![allow(unused_variables)]
#![allow(dead_code)] 
pub mod curve;
mod bigint;
use curve::Curve;
use hacspec_lib::*;
use std::collections::HashSet;


// applies the polynomial to input x
fn apply<T: Curve>(polynomial: &Vec<T::Scalar>, x: &T::Scalar) -> T::Scalar {
    let mut result= T::scalar_from_literal(&0);

    for i in 0..polynomial.len() {
        let term = polynomial[polynomial.len()-1-i] * T::scalar_pow(x, &(i as u128));
        result = result + term;
    }

    result
}


pub struct Pk<T: Curve> {
    g_powers: Vec<T::G1>,
    h_powers: Vec<T::G1>,
    h1: T::G1,
    alpha_g2: T::G2
}



// Prove field properties for multiplication
// Prove associatve laws for addition perhaps ??
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


fn commit_poly<T: Curve>(polynomial: &Vec<T::Scalar> , pk: &Vec<T::G1>, generator: T::G1) -> T::G1 {

    // commit to the original polynomial
    let mut commitment = T::g1_mul(&T::scalar_from_literal(&0), &generator);
    
    let difference = pk.len() - polynomial.len();
    for i in 0..polynomial.len() { 
        let power_index = difference + i;
        
        let current= T::g1_mul(&polynomial[i], &pk[power_index]);
        commitment = T::g1_add(&commitment, &current);
    };
    commitment
}

pub fn setup<T: Curve>(degree: u128, random: &mut Vec<u128>) -> Pk<T> {

    let rand = random.pop().expect("not enough randomness provided");
    let alpha =  T::scalar_from_literal(&rand);

    let mut setup_g1 = Vec::new();
    let mut setup_h1 = Vec::new();
    
    // generate h from some random lambda
    
    let rand = random.pop().expect("not enough randomness provided");
    let h = T::g1_mul(&T::scalar_from_literal(&rand), &T::g1());

    for i in 0..degree + 1 {
        let power: u128 = (degree - i).into();
        let alpha_power= T::scalar_pow(&alpha, &power);

        setup_g1.push(T::g1_mul(&alpha_power, &T::g1()));
        setup_h1.push(T::g1_mul(&alpha_power, &h));
    };
    
    let alpha_g2 = T::g2_mul(&alpha, &T::g2());

    Pk{g_powers : setup_g1, h_powers : setup_h1, h1 : h, alpha_g2}
}


// commit to the set
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

    
    (T::g1_add(&commitment, &hiding_commitment), phi, phi_hat)
}


//creates the witness g^psi(i)h^psi_hat(i)
fn create_witness<T: Curve>(phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, i: T::Scalar, pk: &Pk<T>) 
-> (T::Scalar, T::Scalar, T::Scalar, T::G1) {

    let phi_i  = apply::<T>(&phi, &i);
    let phi_hat_i = apply::<T>(&phi_hat, &i);


    let psi = create_psi::<T>(&phi, phi_i, i);
    let psi_hat = create_psi::<T>(&phi_hat, phi_hat_i, i);

        
    let mut witness = commit_poly::<T>(&psi, &pk.g_powers, T::g1());
    witness = T::g1_add(&witness, &commit_poly::<T>(&psi_hat, &pk.h_powers, pk.h1));

    
    return (i, phi_i, phi_hat_i, witness);
}


pub fn queryzk<T: Curve>(pk: &Pk<T>, set: &HashSet<T::Scalar>, phi: &Vec<T::Scalar>, phi_hat: &Vec<T::Scalar>, kj: T::Scalar, random: &mut Vec<u128>)
-> (T::Scalar, T::G1, Option<T::Scalar>, Option<(T::G1, T::G1, T::G1, T::Scalar, T::Scalar)>) {

    let (kj, phi_kj, phi_hat_kj, witness) = create_witness(phi, phi_hat, kj, pk);
    
    
    if set.contains(&kj) {
        return (kj, witness, Some(phi_hat_kj), None);
    };

    let p1 = T::g1_mul(&phi_kj, &T::g1());
    let p2 = T::g1_mul(&phi_hat_kj, &pk.h1);
    
    
    let proof = T::g1_add(&p1, &p2);

    let (n1, n2, s1, s2) = schnorr_proof(pk, phi_kj, phi_hat_kj, random);

    return (kj, witness, None, Some((proof, n1, n2, s1, s2)));
}



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

    let zero = T::g1_mul(&T::scalar_from_literal(&0), &T::g1());

    let (proof, n1, n2, s1, s2) = pi_sj.expect("invalid state");

    // commiter lied, phi(kj) is in their set
    if n1 == T::g1_mul(&s1, &T::g1()) {
		return false
	}
    
    // we require both proofs to be valid
    if !schnorr_verify::<T>(pk, proof, n1, n2, s1, s2) {
    	return false 
    }


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

fn schnorr_proof<T: Curve>(pk: &Pk<T>, a: T::Scalar, b: T::Scalar, random: &mut Vec<u128>) -> (T::G1, T::G1, T::Scalar, T::Scalar) {
    let r1 = random.pop().expect("not enough randomness provided");
    let r2 = random.pop().expect("not enough randomness provided");
	
    let r1 = T::scalar_from_literal(&r1); 
    let r2 = T::scalar_from_literal(&r2); 

    let n1 = T::g1_mul(&r1, &T::g1());
    let n2 = T::g1_mul(&r2, &pk.h1);
    
    let z1 = T::g1_mul(&a, &T::g1());
    let z2 = T::g1_mul(&b, &pk.h1);
    
    let z = T::g1_add(&z1, &z2);

    let c = T::fiat_shamir_hash(z, n1, n2, pk.h1);

    let s1 = r1 - c * a; 
    let s2 = r2 - c * b; 

    (n1, n2, s1, s2)
}

fn schnorr_verify<T: Curve>(pk: &Pk<T>, z: T::G1, n1: T::G1, n2: T::G1, s1: T::Scalar, s2: T::Scalar) -> bool {
    
    let c = T::fiat_shamir_hash(z, n1, n2, pk.h1);

    let left  = T::g1_add(&n1, &n2);

    let s1 = T::g1_mul(&s1, &T::g1());

    let s2 = T::g1_mul(&s2, &pk.h1);
    
    let z = T::g1_mul(&c, &z);

    let right = T::g1_add(&T::g1_add(&s1, &s2), &z);

    left == right
}




#[cfg(test)]
mod tests {
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
    fn test_schnorr_verification(a: u128, b: u128) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

        let mut random = generate_randomness(5);
        
        let pk: Pk<Curve> = setup(1, &mut random);

        
        let a = Curve::scalar_from_literal(&a);
        let b = Curve::scalar_from_literal(&b);
            
        let p1 = Curve::g1_mul(&a, &Curve::g1());
        let p2 = Curve::g1_mul(&b, &pk.h1);
        
        let proof = Curve::g1_add(&p1, &p2);

            
        let (n1, n2, s1, s2) = schnorr_proof(&pk, a, b, &mut random);
        

        schnorr_verify::<Curve>(&pk, proof, n1, n2, s1, s2)
    }


    #[quickcheck]
    fn test_schnorr_forgery(a: u128, b: u128) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

		let mut random = generate_randomness(20);

		let pk: Pk<Curve> = setup(1, &mut random);

		let a = Curve::scalar_from_literal(&a);
		let b = Curve::scalar_from_literal(&b);
			
		let p1 = Curve::g1_mul(&a, &Curve::g1());
		let p2 = Curve::g1_mul(&b, &pk.h1);
		
		let proof = Curve::g1_add(&p1, &p2);

		// fake knowledge of a by simulating guessing it
		let a = Curve::scalar_from_literal(&random.pop().expect("not enough randomness provided"));

			
		let (n1, n2, s1, s2) = schnorr_proof(&pk, a, b, &mut random);
		

		! schnorr_verify::<Curve>(&pk, proof, n1, n2, s1, s2)
    }

	
	#[quickcheck]
	fn test_schnorr_execution_branch(b: u128) -> bool {
		use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

		let mut random = generate_randomness(20);

		let pk: Pk<Curve> = setup(1, &mut random);

		let a = 0;
		let a = Curve::scalar_from_literal(&a);
		let b = Curve::scalar_from_literal(&b);
			
		let p1 = Curve::g1_mul(&a, &Curve::g1());
		let p2 = Curve::g1_mul(&b, &pk.h1);
		
		let proof = Curve::g1_add(&p1, &p2);

		let (n1, n2, s1, s2) = schnorr_proof(&pk, a, b, &mut random);
		
		n1 == Curve::g1_mul(&s1, &Curve::g1())
	}
    

    #[quickcheck] 
    fn test_kzg_verification(is_in_set: bool) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

        let degree = 10;

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

    
    #[quickcheck] 
    fn test_kzg_forgery(is_in_set: bool) -> bool {
        use curve::SpecCurve as Curve;
        // use curve::FastCurve as Curve;

        let degree = 10;

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
        
        let witness = Curve::g1_mul(&apply::<Curve>(&forged_poly, &kj), &Curve::g1());


        let result = verifyzk(&pk, commitment, pi_sj, kj, witness, phi_hat_kj);

        return ! result
    }
	
    #[quickcheck] 
    fn test_kzg_misdirection() -> bool {
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

		let p1 = Curve::g1_mul(&phi_kj, &Curve::g1());
		let p2 = Curve::g1_mul(&phi_hat_kj, &pk.h1);
		let proof = Curve::g1_add(&p1, &p2);


		let (n1, n2, s1, s2) = schnorr_proof(&pk, phi_kj, phi_hat_kj, &mut random);
		let pi = (proof, n1, n2, s1, s2);


        let result = verifyzk(&pk, commitment, Some(pi), kj, witness, None);

        return ! result
    }
	

}