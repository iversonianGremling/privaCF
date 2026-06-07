(* ===========================================================================
   limb_ve_correctness.ec
   EasyCrypt — DESIGN-f1-verifiable-encryption.md §9 THEOREM 2, algebraic core:
   DECRYPTION CORRECTNESS / RECOVERY. The box, opened with the right key,
   returns exactly the encrypted value.

   This is the algebraic heart of "you can't fake the box": for an honestly
   formed limb ciphertext (U,W) = (g^rho, K^rho * G^m) with K = g^sk, applying
   the decryption (K's secret = the verdict-signature effect) recovers G^m
   exactly. (Full binding against a *malicious* prover adds sigma-protocol
   soundness on top — see limb_ve_binding.ec, the harder remaining piece.)
   =========================================================================== *)

require import AllCore Int Real Distr DBool.
require (*--*) DiffieHellman.

clone DiffieHellman as DH.
import DH.G DH.GP DH.FD DH.GP.ZModE.
clone DH.GP.ZModE.ZModpField as ZPF.

(* The masked limb is W = K^rho * mh where K = g^sk and mh = G^m (a group elt).
   Decryption forms  W * U^(-sk) = (g^sk)^rho * mh * (g^rho)^(-sk).
   Correctness = this equals mh. *)
lemma limb_dec_correct (sk rho : exp) (mh : group) :
  (g ^ sk) ^ rho * mh * (g ^ rho) ^ (-sk) = mh.
proof.
  (* take discrete logs (log_bij): group equation -> field arithmetic, then ring *)
  rewrite log_bij !logDr !logrzM logg1.
  ring.
qed.

(* ---------------------------------------------------------------------------
   BINDING (pillar 2 of Thm 2): a box (U, W) opens to AT MOST ONE plaintext.
   If two openings (mh, rho) and (mh', rho') yield the same ciphertext
   (same U = g^rho, same W = mh * K^rho), they are equal. So no one can open
   the same box to two different secrets — the encryption is a binding
   commitment to its plaintext. (Combined with correctness above and the sigma
   proof certifying well-formedness, this gives full "can't fake the box".)
   --------------------------------------------------------------------------- *)
lemma limb_box_binding (K : group) (rho rho' : exp) (mh mh' : group) :
  g ^ rho = g ^ rho'  =>             (* same U  *)
  mh * K ^ rho = mh' * K ^ rho' =>   (* same W  *)
  rho = rho' /\ mh = mh'.
proof.
  move=> hU hW.
  have hr : rho = rho' by smt(pow_bij).
  split; first exact hr.
  apply log_bij.
  have h : loge (mh * K ^ rho) = loge (mh' * K ^ rho') by rewrite hW.
  move: h; rewrite !logDr hr; smt(@ZPF).
qed.

(* ---------------------------------------------------------------------------
   LIMB-LEVEL binding: when the encoding base G is a generator (loge G <> 0),
   the box commits not just to a unique group element but to a unique *message*
   m (the limb value). So "open to one secret" is at the level of the actual
   limb, not merely G^m.
   --------------------------------------------------------------------------- *)
lemma limb_msg_unique (Gp : group) (m m' : exp) :
  loge Gp <> ZModE.zero =>
  Gp ^ m = Gp ^ m' =>
  m = m'.
proof.
  move=> hG h.
  have hm : m * loge Gp = m' * loge Gp by rewrite -!logrzM h.
  smt(@ZPF).
qed.
