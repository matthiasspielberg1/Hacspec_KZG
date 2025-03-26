use hacspec_bls12_381::*;

pub fn create_trusted_setup (degree: u8, tau: u128) -> (Vec<G1>, G2, G2) {

    let g1_base_point: G1 = g1();
    let g2_base_point: G2 = g2();
    let mut powers_of_tau_g1 = Vec::with_capacity(degree as usize);

    for i in 0..degree {
        powers_of_tau_g1.push(g1mul(Scalar::from_literal(tau.pow(i.into())), g1_base_point));
    };

    let tau_g2 = g2mul(Scalar::from_literal(tau), g2_base_point);
    (powers_of_tau_g1, g2_base_point, tau_g2)

}

pub fn create_commitment (polynomium: &Vec<u128>, setup: (Vec<G1>, G2, G2)) -> G1 {

    let powers_of_tau_g1 = &setup.0;
    let mut commitment = G1::default();

    for i in 0..polynomium.len()-1 {
        let tau_times_coefficient = g1mul(Scalar::from_literal(polynomium[i]), powers_of_tau_g1[i]);
        commitment = g1add(commitment, tau_times_coefficient);
    };

    commitment

}

pub fn calc_request (polynomium: &Vec<u128>, request: u128) -> u128 {

    let mut result: u128 = 0;

    for i in 0..polynomium.len() {
        result = result + polynomium[i] * request.pow(i.try_into().unwrap());
    }

    result

}

pub fn g1() -> G1 {
    (Fp::from_hex("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"),
     Fp::from_hex("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"), false)
}

pub fn g2() -> G2 {
    ((Fp::from_hex("24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
      Fp::from_hex("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")),
     (Fp::from_hex("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
      Fp::from_hex("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let tau = 0xfffffffffffffffffffff;
        let setup = create_trusted_setup(2, tau);
   
        assert_eq!(0, 0);
    }
}
