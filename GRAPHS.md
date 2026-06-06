> **Status note (v0.3.1).** This document captures the *original* design intuitions and the order in which privacy and Sybil-resistance features were composed. Two items have since been superseded by §5.1 of the spec: (1) the transport assumption is no longer a plain VPN but a self-mixing Loopix mixnet, with a Tor/I2P alternate profile; (2) "Temporal decorrelation" is described below as out-of-scope, but the Loopix reference profile brings it **in** scope via per-hop Poisson mixing. Read §5.1 of the spec as authoritative wherever this document disagrees.

The intent of this document is to show a visual representation of the main intuitions behind the design of PrivaCF. First we try to make a decentralized network as private as possible. Then we try to make a network as Sybil resistant as possible. After that we import all of the privacy features that are directly applicable to the Sybil resistant version. Then we describe the technologies that need further tweaking to work.

Technologies/strategies used by the privacy-first architecture:

- VPN
- PSI Handshake
- Noisy/Chopped vector (uniform size)
- Identity rotation
- Loopix
- Regular timings
- Decoy messages
- Decoy aware local system (to prevent degradation of recommendations)


Tecnologies used by the anti-Sybil first network:

- Reputation system
- Locality aware
- Timing aware
- BC commitment
- Behavioral monitoring
- Rate limiting
- Constant audits
- Advanced reputation system
- Entry barrier


We can directly add VPN + regular timings + PSI Handshakes without a problem. The decoy aware local system can be discarded atm as it depends on the successful implementation of Noisy/Chopped vectors. That leaves us with the need to adapt for:

- Noisy/Chopped vector (uniform size with decoys)
- Identity rotation
- Loopix (temporal decorrelation)
- Decoy messages

These two combined give the user an immediate privacy gain:

- Transmitting a noisy/chopped vector of uniform size is needed to protect the user preferences
- Identity rotation is needed to ensure that users are harder to link 

The remaining two are needed to prevent metadata tracking:

- Loopix (temporal correlation)
- Decoy messages (plausible deniability)

## Implementing noisy/chopped vector

The problem with adding a noisy/chopped vector is that we lose the ability to ensure that two vectors are not extremely similar (which could be a signal for a Sybil attack)

For this we propose:

- Each nodes computes PSI locally
- If they find "strangely similar" signals that to the committee
- Committee forces them to send a proof of their PSI overlap

## Implementing Identity Rotation

Identity rotation is considerably hard without breaking the anti-sybil guarantees:

- Reputation system

- Locality awareness

- Timing awareness

- BC commitment

- Advanced reputation/behavioral monitoring

- Constant audits

- Advanced reputation system

  

- We use a system of epochs for the whole network
- The epochs are desynchronized from each other but each nodes makes commitments whenever they rotate
- Failure to do so results in an audit by nodes of a committee
- Each epoch a node uses their sk to create a new identity and they submit a proof of continuity
- The proofs of continuity are checked, failure results in an audit of a committee
- When each node starts activity on the network they advertise their epoch_ID
- Inside that epoch ID there's a null_v value that is secret. null_v can be proven to be linked to any particular epoch ID, all of them would match null_v
- The keys for invalidating a null_v value are accessible to any committee
- The committee must add a verdict +  the null_v to the blockchain, they must also sign it making them accountable
- In case the committee goes rogue they wouldn't be able to do that without committing to the blockchain which would trigger a watchdog protocol creating a new committee, potentially triggering suspension of the nodes
- Since committee members are known based on a common source of entropy they can be held accountable in case of abuse within the same epoch
- Nodes check periodically if a certain node they are interacting with has been nullified before initiating any operation based on their epoch ID
- The reputation of each node is divided into n bands, it's tied to the nodes IDs as a part of their proof of continuity
- The construction of the proof of continuity has to be tested to be valid and follow the stated properties
- If everything works well we have constructed a system that successfully creates accountability and allows us to fulfill these properties/technologies:
  - Reputation system
  - Locality awareness
  - Timing awareness
  - BC commitment
  - Advanced reputation/behavioral monitoring

- Constant audits have to be implemented on the whole protocol, mainly through Merkle trees, Pedersen commitments, zk-proofs and other ways that allow to reveal information without revealing the data

## Temporal decorrelation

Temporal decorrelation is, currently, impossible to implement alongside behavioral profiling technologies that we have. If a user decides to have it they should follow OPSEC principles and use networks that support it. Out of scope.

## Decoy messages

Decoy messages were added to increase the theoretical anonymity capabilities of the network. Two possible constructions of them are:

- Decoy messages that are distinguishable only by a committee with the signed/blockchain properties previously described
- Decoy messages are indistinguishable from any other message

In the second case we have to ensure that decoy messages can't cause false positives (negative reputation), or severe distortion of the recommendations

The first condition isn't hard to fulfill as long as the messages are properly designed, the second one requires a bit more nuance to balance with the indistinguishability property. Their main purpose is to create "plausible deniability".

That requires for them to be fundamentally different from the ones that the user would send normally.

One way would be committing to several Pedersen commitments, some of them being false.

This method would make some audits harder but if we can verify if a certain PSI overlap would occur with them.
If that doesn't work maybe we can use HE and hand it to a committee in case something goes wrong