(* ===========================================================================
   limb_ve_indcpa.ec
   EasyCrypt PROOF — DESIGN-f1-verifiable-encryption.md §9 THEOREM 1:
   IND-CPA confidentiality of one limb of the limb verifiable encryption,
   reduced to DDH.

   KEY OBSERVATION that makes this a real (not hand-rolled) proof:
   the limb ciphertext  (U, W) = ( g^rho ,  K^rho * G^m )  is *exactly* ElGamal
   encryption of the group element  G^m  under public key  K  (= e(Q_id,P),
   modeled as the recipient base g^x). So per-limb confidentiality IS ElGamal
   IND-CPA: hiding G^{m0} vs G^{m1} ⟺ hiding the limb m0 vs m1 (G injective on
   exponents). We therefore instantiate EasyCrypt's DDH + PKE_CPA machinery and
   reuse the standard ElGamal IND-CPA proof (adapted from theories examples).

   The pairing is abstracted exactly as in DESIGN §9: the mask e(Q_id,P)^rho is
   the ElGamal term K^rho with K = g^x public; confidentiality reduces to DDH
   here (to DBDH in the ROM in the real instantiation — same proof shape).

   STATUS: MILESTONE 2 — this file is PROVED (no `admit`): the `conclusion`
   lemma bounds the per-limb IND-CPA advantage by the DDH advantage, checked by
   EasyCrypt with Z3/Alt-Ergo. The k-limb bound (DESIGN §9: k * eps) is a hybrid
   over independent rho_j, left as the next step.
   =========================================================================== *)

require import AllCore Int Real Distr DBool.
require (*--*) DiffieHellman PKE_CPA.

pragma +implicits.

(* DDH assumption over a prime-order cyclic group *)
clone DiffieHellman as DH.
import DH.DDH DH.G DH.GP DH.FD DH.GP.ZModE.
clone DH.GP.ZModE.ZModpField as ZPF.

(* The PKE the limb encryption instantiates. ptxt = group: the encrypted object
   is the limb-encoding G^m (a group element). *)
type pkey = group.       (* K = e(Q_id, P), modeled as g^x *)
type skey = exp.         (* the verdict-signature effect; unused by enc (CPA) *)
type ptxt = group.       (* the limb encoded as G^m *)
type ctxt = group * group.  (* (U, W) = (g^rho, K^rho * G^m) *)

clone import PKE_CPA as PKE with
  type pkey <- pkey,
  type skey <- skey,
  type ptxt <- ptxt,
  type ctxt <- ctxt.

(* One-limb verifiable encryption = ElGamal on the limb-encoding G^m. *)
module LimbVE : Scheme = {
  proc kg(): pkey * skey = {
    var sk;
    sk <$ dt;
    return (g ^ sk, sk);          (* K = g^sk *)
  }

  proc enc(pk:pkey, m:ptxt): ctxt = {
    var y;
    y <$ dt;
    return (g ^ y, pk ^ y * m);   (* (U, W) = (g^rho, K^rho * G^m) *)
  }

  proc dec(sk:skey, c:ctxt): ptxt option = {
    var gy, gm;
    (gy, gm) <- c;
    return Some (gm * gy ^ (-sk)); (* recovers G^m; then BSGS the limb (off-circuit) *)
  }
}.

(* Reduction: a per-limb IND-CPA adversary yields a DDH distinguisher. *)
module DDHAdv (A:Adversary) = {
  proc guess (gx, gy, gz) : bool = {
    var m0, m1, b, b';
    (m0, m1) <@ A.choose(gx);
    b        <$ {0,1};
    b'       <@ A.guess(gy, gz * (b?m1:m0));
    return b' = b;
  }
}.

section Security.
  declare module A <: Adversary.
  declare axiom Ac_ll: islossless A.choose.
  declare axiom Ag_ll: islossless A.guess.

  local lemma cpa_ddh0 &m:
      Pr[CPA(LimbVE,A).main() @ &m : res] =
      Pr[DDH0(DDHAdv(A)).main() @ &m : res].
  proof.
  byequiv=> //; proc; inline *.
  swap{1} 7 -5.
  auto; call (_:true).
  auto; call (_:true).
  by auto=> /> sk _ y _ r b _; rewrite expM.
  qed.

  local module Gb = {
    proc main () : bool = {
      var x, y, z, m0, m1, b, b';
      x       <$ dt;
      y       <$ dt;
      (m0,m1) <@ A.choose(g ^ x);
      z       <$ dt;
      b'      <@ A.guess(g ^ y, g ^ z);
      b       <$ {0,1};
      return b' = b;
    }
  }.

  local lemma ddh1_gb &m:
      Pr[DDH1(DDHAdv(A)).main() @ &m : res] =
      Pr[Gb.main() @ &m : res].
  proof.
  byequiv=> //; proc; inline *.
  swap{1} 3 2; swap{1} [5..6] 2; swap{2} 6 -2.
  auto; call (_:true); wp.
  rnd (fun z, z + loge (if b then m1 else m0){2})
      (fun z, z - loge (if b then m1 else m0){2}).
  auto; call (_:true).
  auto; progress.
  - by rewrite ZPF.addrAC -ZPF.addrA ZPF.subrr ZPF.addr0.
  - by rewrite  -ZPF.addrA ZPF.subrr ZPF.addr0.
  - by rewrite expD expgK.
  qed.

  local lemma Gb_half &m:
     Pr[Gb.main()@ &m : res] = 1%r/2%r.
  proof.
  byphoare=> //; proc.
  rnd  (pred1 b')=> //=.
  conseq (: _ ==> true).
  + by move=> /> b; rewrite dbool1E pred1E.
  islossless;[ apply Ag_ll | apply Ac_ll].
  qed.

  (* THEOREM 1 (DESIGN §9): per-limb IND-CPA advantage <= DDH advantage. *)
  lemma conclusion &m :
    `| Pr[CPA(LimbVE,A).main() @ &m : res] - 1%r/2%r | =
    `| Pr[DDH0(DDHAdv(A)).main() @ &m : res] -
         Pr[DDH1(DDHAdv(A)).main() @ &m : res] |.
  proof.
  by rewrite (cpa_ddh0 &m) (ddh1_gb &m) (Gb_half &m).
  qed.
end section Security.

print conclusion.
