module Hacspec_sha256
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

// Stub for hacspec SHA256 implementation
type t_Digest = unit
type t_Sha256Digest = unit

let hash (input: Hacspec_lib.Seq.t_Seq Secret_integers.t_U8) : t_Sha256Digest = ()
