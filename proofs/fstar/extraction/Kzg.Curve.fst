module Kzg.Curve
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

class t_Curve (v_Self: Type0) = {
  f_G1:Type0;
  f_G1_4015329557539960005:Core.Cmp.t_Eq f_G1;
  f_G1_18123083762528165743:Core.Marker.t_Copy f_G1;
  f_G1_10771508119931921386:Core.Fmt.t_Debug f_G1;
  f_G2:Type0;
  f_G2_13207800682162281212:Core.Cmp.t_Eq f_G2;
  f_G2_5681580312493623606:Core.Marker.t_Copy f_G2;
  f_G2_13482855656860714102:Core.Fmt.t_Debug f_G2;
  f_Scalar:Type0;
  f_Scalar_465262235997129610:Core.Cmp.t_Eq f_Scalar;
  f_Scalar_11889989266480416936:Core.Ops.Arith.t_Add f_Scalar f_Scalar;
  f_Scalar_13148136570248258261:Core.Ops.Arith.t_Sub f_Scalar f_Scalar;
  f_Scalar_16952074095676050873:Core.Ops.Arith.t_Mul f_Scalar f_Scalar;
  f_Scalar_6984880678016443449:Core.Marker.t_Copy f_Scalar;
  f_Scalar_2061965257658105702:Core.Hash.t_Hash f_Scalar;
  f_Scalar_4355230273732225505:Core.Fmt.t_Display f_Scalar;
  f_Scalar_8296382249976294297:Core.Fmt.t_Debug f_Scalar;
  f_Element:Type0;
  f_Element_12253850604889343678:Core.Cmp.t_Eq f_Element;
  f_Element_1338311712094683471:Core.Fmt.t_Debug f_Element;
  f_scalar_from_literal_pre:u128 -> Type0;
  f_scalar_from_literal_post:u128 -> f_Scalar -> Type0;
  f_scalar_from_literal:x0: u128
    -> Prims.Pure f_Scalar
        (f_scalar_from_literal_pre x0)
        (fun result -> f_scalar_from_literal_post x0 result);
  f_scalar_pow_pre:f_Scalar -> u128 -> Type0;
  f_scalar_pow_post:f_Scalar -> u128 -> f_Scalar -> Type0;
  f_scalar_pow:x0: f_Scalar -> x1: u128
    -> Prims.Pure f_Scalar (f_scalar_pow_pre x0 x1) (fun result -> f_scalar_pow_post x0 x1 result);
  f_g1mul_pre:f_Scalar -> f_G1 -> Type0;
  f_g1mul_post:f_Scalar -> f_G1 -> f_G1 -> Type0;
  f_g1mul:x0: f_Scalar -> x1: f_G1
    -> Prims.Pure f_G1 (f_g1mul_pre x0 x1) (fun result -> f_g1mul_post x0 x1 result);
  f_g2mul_pre:f_Scalar -> f_G2 -> Type0;
  f_g2mul_post:f_Scalar -> f_G2 -> f_G2 -> Type0;
  f_g2mul:x0: f_Scalar -> x1: f_G2
    -> Prims.Pure f_G2 (f_g2mul_pre x0 x1) (fun result -> f_g2mul_post x0 x1 result);
  f_g1add_pre:f_G1 -> f_G1 -> Type0;
  f_g1add_post:f_G1 -> f_G1 -> f_G1 -> Type0;
  f_g1add:x0: f_G1 -> x1: f_G1
    -> Prims.Pure f_G1 (f_g1add_pre x0 x1) (fun result -> f_g1add_post x0 x1 result);
  f_g2add_pre:f_G2 -> f_G2 -> Type0;
  f_g2add_post:f_G2 -> f_G2 -> f_G2 -> Type0;
  f_g2add:x0: f_G2 -> x1: f_G2
    -> Prims.Pure f_G2 (f_g2add_pre x0 x1) (fun result -> f_g2add_post x0 x1 result);
  f_g1sub_pre:f_G1 -> f_G1 -> Type0;
  f_g1sub_post:f_G1 -> f_G1 -> f_G1 -> Type0;
  f_g1sub:x0: f_G1 -> x1: f_G1
    -> Prims.Pure f_G1 (f_g1sub_pre x0 x1) (fun result -> f_g1sub_post x0 x1 result);
  f_g2sub_pre:f_G2 -> f_G2 -> Type0;
  f_g2sub_post:f_G2 -> f_G2 -> f_G2 -> Type0;
  f_g2sub:x0: f_G2 -> x1: f_G2
    -> Prims.Pure f_G2 (f_g2sub_pre x0 x1) (fun result -> f_g2sub_post x0 x1 result);
  f_g1_pre:Prims.unit -> Type0;
  f_g1_post:Prims.unit -> f_G1 -> Type0;
  f_g1:x0: Prims.unit -> Prims.Pure f_G1 (f_g1_pre x0) (fun result -> f_g1_post x0 result);
  f_g2_pre:Prims.unit -> Type0;
  f_g2_post:Prims.unit -> f_G2 -> Type0;
  f_g2:x0: Prims.unit -> Prims.Pure f_G2 (f_g2_pre x0) (fun result -> f_g2_post x0 result);
  f_pairing_pre:f_G1 -> f_G2 -> Type0;
  f_pairing_post:f_G1 -> f_G2 -> f_Element -> Type0;
  f_pairing:x0: f_G1 -> x1: f_G2
    -> Prims.Pure f_Element (f_pairing_pre x0 x1) (fun result -> f_pairing_post x0 x1 result);
  f_fiat_shamir_hash_pre:f_G1 -> f_G1 -> f_G1 -> f_G1 -> Type0;
  f_fiat_shamir_hash_post:f_G1 -> f_G1 -> f_G1 -> f_G1 -> f_Scalar -> Type0;
  f_fiat_shamir_hash:x0: f_G1 -> x1: f_G1 -> x2: f_G1 -> x3: f_G1
    -> Prims.Pure f_Scalar
        (f_fiat_shamir_hash_pre x0 x1 x2 x3)
        (fun result -> f_fiat_shamir_hash_post x0 x1 x2 x3 result)
}
