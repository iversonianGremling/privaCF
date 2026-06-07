(* ===========================================================================
   limb_ve_soundness.ec
   EasyCrypt — DESIGN-f1-verifiable-encryption.md §9 THEOREM 2, protocol piece:
   SPECIAL-SOUNDNESS of the verifiable-encryption sigma proof.

   The sigma proof certifies a box (U, W) is well-formed: U = g^rho and
   W = G^m * K^rho. Special-soundness = "the check catches fakes": if a prover
   can answer TWO different challenges (c1 <> c2) for the SAME commitment
   (A, B), then a valid witness can be EXTRACTED — so the prover wasn't bluffing,
   the box really is of the certified form.

   Verifier equations (Schnorr-style representation proof), per transcript i:
       g ^ zr_i              = A * U ^ c_i        (binds rho in U)
       G ^ zm_i * K ^ zr_i   = B * W ^ c_i        (binds (m,rho) in W)

   We prove the extraction relation in multiplicative form (no field inverse
   needed): two accepting transcripts pin U and W to the extracted exponents.
   Dividing by (c1 - c2) (a unit since c1 <> c2) gives the actual witness
   rho = (zr1-zr2)/(c1-c2), m = (zm1-zm2)/(c1-c2) with U = g^rho, W = G^m K^rho.

   NOTE this is the *algebraic* special-soundness (extraction works). Wrapping it
   in a probabilistic proof-of-knowledge (rewinding extractor) is the standard
   remaining step; the algebraic core below is the part that says "you cannot
   answer two challenges without a real opening".
   =========================================================================== *)

require import AllCore Int Real Distr DBool.
require (*--*) DiffieHellman.

clone DiffieHellman as DH.
import DH.G DH.GP DH.FD DH.GP.ZModE.
clone DH.GP.ZModE.ZModpField as ZPF.

lemma sigma_extract
  (Kp Gp Uu Wc Ac Bc : group) (c1 c2 zm1 zr1 zm2 zr2 : exp) :
  g ^ zr1            = Ac * Uu ^ c1 =>
  Gp ^ zm1 * Kp ^ zr1 = Bc * Wc ^ c1 =>
  g ^ zr2            = Ac * Uu ^ c2 =>
  Gp ^ zm2 * Kp ^ zr2 = Bc * Wc ^ c2 =>
  Uu ^ (c1 - c2) = g ^ (zr1 - zr2) /\
  Wc ^ (c1 - c2) = Gp ^ (zm1 - zm2) * Kp ^ (zr1 - zr2).
proof.
  move=> h1 h2 h3 h4.
  (* take discrete logs of each verifier equation -> linear field facts *)
  have L1: zr1 = loge Ac + c1 * loge Uu.
    by rewrite -(loggK zr1) h1 logDr logrzM.
  have L3: zr2 = loge Ac + c2 * loge Uu.
    by rewrite -(loggK zr2) h3 logDr logrzM.
  have L2: zm1 * loge Gp + zr1 * loge Kp = loge Bc + c1 * loge Wc.
    by rewrite -logrzM -logrzM -logDr h2 logDr logrzM.
  have L4: zm2 * loge Gp + zr2 * loge Kp = loge Bc + c2 * loge Wc.
    by rewrite -logrzM -logrzM -logDr h4 logDr logrzM.
  split.
  - (* U^(c1-c2) = g^(zr1-zr2): logs -> (c1-c2)*loge Uu = zr1 - zr2 *)
    apply log_bij; rewrite logrzM loggK L1 L3; ring.
  - (* W^(c1-c2) = G^(zm1-zm2) * K^(zr1-zr2) *)
    apply log_bij; rewrite logDr !logrzM.
    (* goal: (c1-c2)*loge Wc = (zm1-zm2)*loge Gp + (zr1-zr2)*loge Kp *)
    have d2 : (zm1 * loge Gp + zr1 * loge Kp) - (zm2 * loge Gp + zr2 * loge Kp)
              = (c1 - c2) * loge Wc.
      by rewrite L2 L4; ring.
    rewrite eq_sym; rewrite -d2; ring.
qed.
