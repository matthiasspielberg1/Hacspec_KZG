module Kzg
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Hacspec_bls12_381_ in
  let open Hacspec_lib.Seq in
  let open Hacspec_lib.Traits in
  let open Hacspec_sha256 in
  let open Secret_integers in
  ()

let g1 (_: Prims.unit) : (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) =
  Hacspec_bls12_381_.impl_Fp__from_hex "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
  ,
  Hacspec_bls12_381_.impl_Fp__from_hex "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
  ,
  false
  <:
  (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool)

type t_PkVerifiable = {
  f_g_powers:Alloc.Vec.t_Vec (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool)
    Alloc.Alloc.t_Global;
  f_h_powers:Alloc.Vec.t_Vec (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool)
    Alloc.Alloc.t_Global;
  f_h1:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool);
  f_alpha_g2:((Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp) &
    (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp) &
    bool)
}

let g1_to_byte_seq_verifiable (g: (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
    : Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 =
  let x, y, inf:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) = g in
  let x_bytes:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 =
    Hacspec_bls12_381_.impl_Fp__to_byte_seq_be x
  in
  let result:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 =
    Hacspec_lib.Seq.impl_41__concat #Secret_integers.t_U8
      #(Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
      x_bytes
      (Hacspec_bls12_381_.impl_Fp__to_byte_seq_be y <: Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
  in
  let inf_bytes:Secret_integers.t_U8 = Secret_integers.impl_U8__zero () in
  let inf_bytes:Secret_integers.t_U8 =
    if inf
    then
      let inf_bytes:Secret_integers.t_U8 = Secret_integers.impl_U8__one () in
      inf_bytes
    else inf_bytes
  in
  Hacspec_lib.Seq.impl_41__push #Secret_integers.t_U8 result inf_bytes

let fiat_shamir_hash_verifiable
      (z n1 n2 h: (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
    : Hacspec_bls12_381_.t_Scalar =
  let g:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 =
    g1_to_byte_seq_verifiable (g1 () <: (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
  in
  let h:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 = g1_to_byte_seq_verifiable h in
  let z:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 = g1_to_byte_seq_verifiable z in
  let n1:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 = g1_to_byte_seq_verifiable n1 in
  let n2:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 = g1_to_byte_seq_verifiable n2 in
  let bytes:Hacspec_lib.Seq.t_Seq Secret_integers.t_U8 =
    Hacspec_lib.Seq.impl_41__concat #Secret_integers.t_U8
      #(Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
      (Hacspec_lib.Seq.impl_41__concat #Secret_integers.t_U8
          #(Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
          (Hacspec_lib.Seq.impl_41__concat #Secret_integers.t_U8
              #(Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
              (Hacspec_lib.Seq.impl_41__concat #Secret_integers.t_U8
                  #(Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
                  g
                  h
                <:
                Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
              z
            <:
            Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
          n1
        <:
        Hacspec_lib.Seq.t_Seq Secret_integers.t_U8)
      n2
  in
  let digest:Hacspec_sha256.t_Sha256Digest = Hacspec_sha256.hash bytes in
  Hacspec_bls12_381_.impl_Scalar__from_byte_seq_be #Hacspec_sha256.t_Sha256Digest digest

let schnorr_verify_verifiable
      (pk: t_PkVerifiable)
      (z n1 n2: (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
      (s1 s2: Hacspec_bls12_381_.t_Scalar)
    : bool =
  let c:Hacspec_bls12_381_.t_Scalar = fiat_shamir_hash_verifiable z n1 n2 pk.f_h1 in
  let left:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) =
    Hacspec_bls12_381_.g1add n1 n2
  in
  let s1:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) =
    Hacspec_bls12_381_.g1mul s1
      (g1 () <: (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
  in
  let s2:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) =
    Hacspec_bls12_381_.g1mul s2 pk.f_h1
  in
  let z:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) = Hacspec_bls12_381_.g1mul c z in
  let right:(Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool) =
    Hacspec_bls12_381_.g1add (Hacspec_bls12_381_.g1add s1 s2
        <:
        (Hacspec_bls12_381_.t_Fp & Hacspec_bls12_381_.t_Fp & bool))
      z
  in
  left =. right
