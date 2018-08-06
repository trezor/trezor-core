# Monero

MAINTAINER = ...

AUTHOR = Dusan Klinec <dusan.klinec@gmail.com>

REVIEWER = ...

ADVISORS =

-----

This Monero implementation was implemented from scratch originally for TREZOR by porting Monero C++ code to the Python codebase.

The implementation heavily relies on the [trezor-crypto] Monero functionality which implements basic crypto primitives and
other Monero related functionality (e.g., monero base58, accelerated and optimized Borromean range signatures)

A general high level description of the integration proposal is described in the documentation: [monero-doc].

## Features

The implementation provides the following features:

### Transaction signature

Signs a Monero transaction on the TREZOR.

- Designed so number of UTXO is practically unlimited (hundreds to thousands)
- Maximal number of outputs per transaction is 8 (usually there are only 2)
- Supports 8 B encrypted payment ID and 32 B unencrypted payment ID.

### Key Image sync

Key Image is computed with the spend key which is stored on the TREZOR.

In order to detect if the UTXO has been already spent (thus computing balance due to change transactions)
and correct spending UTXOs the key images are required. Without the key images the Monero view only
wallet incorrectly computes balance as it sees all ever received transactions as unspent.

Key image sync is a protocol that allows to compute key images for incoming transfers by TREZOR.

Example: 20 XMR in the single UTXO is received, thus real balance is 20. 1 XMR is sent to a different
address and remaining 19 are sent back with a change transaction. Correct balance is 19 but without
correct key image the view only wallet shows balance 39. Without knowing which UTXO is spent
the newly constructed spending transactions can pick already spent input. Such transaction is
rejected by a Monero daemon as a double spending transaction.

Normally, the Key image sync is not needed as the key image computation is done by
the transaction signing algorithm. However, if the wallet file is somehow corrupted
or the wallet is used on a new host / restored from the TREZOR the key
image sync is required for correct function of the wallet. It recomputes key images
for all received transaction inputs.


## Integration rationale

The Monero codebase already contains cold wallet support. I.e., wallet not connected to the Internet, which should provide
better security guarantees as it minimizes attack surface compared to the hot wallet - always connected wallet.

As the cold wallet is not connected to the Internet and does not have access nor to the blockchain neither to the monero
full node the all information for transaction construction have to be prepared by the hot wallet.

When using the cold wallet, hot wallet is watch-only. It has only the view-key so it can scan blockchain for incoming
transactions but is not able to spend any transaction.

Transaction signature with cold wallet works like this:

- Create transaction construction data on hot wallet. `transfer <address> <amount>`. Works similar to the normal wallet operation
but instead of the signed transaction, the watch-only hot wallet generates `unsigned_txset` file which contains
transaction construction data.

- Cold wallet opens `unsigned_txset`, verifies the signature on the transaction construction data and creates Monero transaction
using the data. Cold wallet creates `signed_txset`

- Hot wallet opens `signed_txset`, verifies the transaction and asks user whether to submit transaction to the full node.

### Cold wallet protocols

As cold wallet support is already present in Monero codebase, the protocols were well designed and analyzed.
We decided to reuse the cold wallet approach when signing the transaction as the TREZOR pretty much behaves as the cold wallet,
i.e., does not have access to the blockchain or full Monero node. The whole transaction is built in the TREZOR thus
the integration has security properties of the cold wallet (which is belevied to be secure). This integration approach
makes security analysis easier and enables to use existing codebase and protocols. This makes merging TREZOR support to
the Monero codebase easier.
We believe that by choosing a bit more high-level approach in the protocol design we could easily add more advanced features,

TREZOR implements cold wallet protocols in this integration scheme.


## Description

Main high level protocol logic is implemented in `apps/monero/protocol/` directory.

### Serialization

The serialization in `apps/monero/xmr/serialize` is the cryptonote serialization format used to serialize data to blockchain.
The serialization was ported from Monero C++. Source comes from the library [monero-serialize].

Serialization scheme was inspired by protobuf serialization scheme. Later it was subject to optimizations as
scheme definition with `FIELDS` attribute was quite memory hungry. Serialization was refactred to specify
fields as a classmethod which is easier to `gc.collect()` after serialization is done compared to static `FIELDS`
which are not easy to deallocate.

```python
    @classmethod
    def f_specs(cls):
        return (("size", SizeT),)
```

Serialization works in `async/wait` manner, uses `reader/writer` interface as protobuf uses.

Moreover the serialization funtionality is encapsulated in so-called Archive object which encapsulates serialization logic.
Archive works in a symmetric way, i.e., the same API is used for serialization and deserialization.


### Protocols

Transaction signing and Key Image (KI) sync are multi-step stateful protocols.
The protocol have several roundtrips.

In the signing protocol the connected host mainly serves as a dumb storage providing values to the TREZOR when needed,
mainly due to memory constrains on TREZOR. The offloaded data can be in plaintext. In this case data is HMACed with unique HMAC
key to avoid data tampering, reordering, replay, reuse, etc... Some data are offloaded as protected, encrypted and authenticated
with Chacha20Poly1305 with unique key (derived from the protocol step, message, purpose, counter, master secret).

TREZOR builds the signed Monero transaction incrementally, i.e., one UTXO per round trip, one transaction output per roundtrip.

### Protocol wrapping messages

Due to the dispatcher design we decided to use wrapping message for the multi-step protocols.
The top wrapping message contains sub-message field for each possible message in the protocol. In this way we can register
one simple dispatcher on the wrapping message and do the sub-message multiplexing in the code, hidden in the abstraction.

Without wrapping message we would have to register each sub-message to the same handler and then de-multiplex it again
in the protocol logic which is error prone and duplicates the code. When changing the flow later it would be prone to errors.

Responses are not wrapped and each response has own wire ID. Response messages are not registered so we don't need wrapping.

Protobuf messages are following the convention `MoneroXRequest`, `MoneroXAck`.


## Key Image sync work flow

In the KI sync cold wallet protocol KIs are generated by the cold wallet. For each KI there is a ring signature
generated by the cold wallet (KI proof).

KI sync is mainly needed to recover from some problem or when using a new hot-wallet (corruption of a wallet file or
using TREZOR on a different host).

The KI protocol has 3 steps. Wrapping message `MoneroKeyImageSyncRequest`.

### Init step

- `MoneroKeyImageExportInitRequest`
- Contains commitment to all KIs we are going to compute (hash of all UTXOs).
- User can confirm / reject the KI sync in this step. Init message contains number of KIs for computation.

### Sync

- `MoneroKeyImageSyncStepRequest`
- Computes N KIs in this step. N = 10 for now.
- Returns encrypted result, `MoneroExportedKeyImage`

### Finalization

- `MoneroKeyImageSyncFinalRequest`
- When commitment on all KIs is correct (i.e, number of UTXOs matches, hashes match) the encryption key is released
to the agent/hot-wallet so it can decrypt computed KIs and import it


## Transaction signing

For detailed description and rationale please refer to the [monero-doc].

TODO

- The wrapping message: `MoneroTransactionSignRequest`.
- The main multiplexor: `apps/monero/protocol/tsx_sign.py`
- The main signing logic is implemented in `apps/monero/protocol/tsx_sign_builder.py`
- State automaton watching correct state transitions: `apps/monero/protocol/tsx_sign_state.py`
- State hold between protocol messages: `apps/monero/protocol/tsx_sign_state_holder.py`. The state is externalized in the
dedicated class so the memory consumption is minimal between round trips.


### `MoneroTransactionInitRequest`:

- Contains basic construction data for the transaction, e.g., transaction destinations, fee, mixin level,
range proof details (type of the range proof, batching scheme).

After receiving this message:
- The TREZOR prompts user for verification of the destination addresses and amounts.
- Commitments are computed thus later potential deviations from transaction destinations are detected and signing aborts.
- Secrets for HMACs / encryption are computed, TX key is computed.
- Precomputes sub-addresses if needed.

### `MoneroTransactionSetInputRequest`

- Sends one UTXO to the TREZOR for processing, encoded as `MoneroTransactionSourceEntry`.
- Contains construction data needed for signing the transaction, computing spending key for UTXO.

TREZOR computes spending keys, `TxinToKey`, `pseudo_out`, HMACs for offloaded data

### `MoneroTransactionInputsPermutationRequest`

UTXOs have to be sorted by the key image in the valid blockchain transaction.
This message caries permutation on the key images so they are sorted in the desired way.

### `MoneroTransactionInputViniRequest`

- Step needed to correctly hash all transaction inputs, in the right order computed in the previous step.
- Contains `MoneroTransactionSourceEntry` and `TxinToKey` computed in the previous step.
- TREZOR Computes `tx_prefix_hash` is part of the signed data.


### `MoneroTransactionAllInputsSetRequest`

- Sent after all inputs have been processed.
- Mainly used in the range proof offloading to the host. E.g., in case of batched Bulletproofs with more than 2 transaction outputs.
The message response can carry commitment masks so host can compute range proof correctly.

### `MoneroTransactionSetOutputRequest`

- Sends transaction output, `MoneroTransactionDestinationEntry`, one per message.
- HMAC prevents tampering with previously accepted data (in the init step).
- TREZOR computes data related to transaction output, e.g., range proofs, ECDH info for the receiver, output public key.
- In case offloaded range proof is used the request can carry computed range proof.

### `MoneroTransactionRangeSigRequest`

- Optional protocol message that supports more complicated, several round-trips range proof offloading proposals as described in the [monero-doc].
- Not used with the basic range proof offloading where the whole range proof is computed on the host.

### `MoneroTransactionAllOutSetRequest`

Sent after all transaction outputs have been sent to the TREZOR for processing.
Request is empty, the response contains computed `extra` field (may contain additional public keys if sub-addresses are used),
computed `tx_prefix_hash` and basis for the final transaction signature `MoneroRingCtSig` (fee, transaction type).

### `MoneroTransactionMlsagDoneRequest`

Message sent to ask TREZOR to compute pre-MLSAG hash required for the signature.
Hash is computed incrementally by TREZOR since the init message and can be finalized in this step.
Request is empty, response contains message hash, required for the signature.

### `MoneroTransactionSignInputRequest`

- Caries `MoneroTransactionSourceEntry`, similarly as previous messages `MoneroTransactionSetInputRequest`, `MoneroTransactionInputViniRequest`.
- Caries computed transaction inputs, pseudo outputs, HMACs, encrypted spending keys and alpha masks
- TREZOR generates MLSAG for this UTXO, returns the signature.
- Code returns also `cout` value if the multisig mode is active - not fully implemented, will be needed later when implementing multisigs.

### `MoneroTransactionFinalRequest`

- Sent when all UTXOs have been signed properly
- Finalizes transaction signature
- Returns encrypted transaction private keys which are needed later, e.g. for TX proof. As TREZOR cannot store aux data
for all signed transactions its offloaded encrypted to the wallet. Later when TX proof is implemented in the TREZOR it
will load encrypted TX keys, decrypt it and generate the proof.


## Implementation notes

Few notes on desing / implementation.

### Cryptography

Operation with Ed25519 points and scalars are implemented in [trezor-crypto] so the underlying cryptography layer
is fast, secure and constant-time.

Ed Point coordinates are Extended Edwards, using type `ge25519` with coordinates `(x, y, z, t)`. Functions in Monero code
in the [trezor-crypto] use the `ge25519` for points (no other different point formats).

Functions like `op256_modm` (e.g., `add256_modm`) operate on scalar values, i.e., 256 bit integers modulo curve order
`2**252 + 3*610042537739*15158679415041928064055629`.

Functions `curve25519_*` operate on 256 bit integers modulo `2**255 - 19`, the coordinates of the point.
These are used mainly internally (e.g., for `hash_to_point()`) and not exported to the [trezor-core].

[trezor-crypto] contains also some Monero-specific functions, such as
`xmr_hash_to_scalar`, `xmr_hash_to_ec`, `xmr_generate_key_derivation`. Those are used in [trezor-core] where more high
level operations are implemented, such as MLSAG.

#### Crypto API

API bridging [trezor-crypto] and [trezor-core]: `embed/extmod/modtrezorcrypto/modtrezorcrypto-monero.h`

It encapsulates Ed25519 points and scalars in corresponding Python classes which have memory-wiping destructor.
API provides basic functions for work with scalars and points and Monero specific functions.

The API is designed in such a way it is easy to work with Ed25519 as there is only one point format which is always
normed to avoid complications when chaining operations such as `scalarmult`s.

### Point normalization

Points in [trezor-core] are normed, i.e., `z=1`.

Normalization is mainly needed after `ge25519_scalarmult`, `ge25519_scalarmult_base_niels`,
which is already done in Monero code in [trezor-crypto].

if the norming is not performed, the operations could not be chained arbitrarily as the result is invalid.

Note:
Point normalization operation is typically performed when compressing coordinate point representation to the 32 B array
as `z` needs to be 1. It requires to compute inversion which is not for free.

On the other hand, the original Monero C++ code typically operates on 32 B keys by
decompressing and compressing it after each result so they are doing normalization in each step, basically.

There are some optimized chunks, e.g., range sig verification, which improves blockchain scanning
(still takes 3 days to verify the blockchain).
Optimized chunks are using different point representations to avoid redundant normalizations but in general cases,
it is not a performance issue for the sake of correct computation, easy development and maintenance.

### Range signatures

Borromean range signatures were optimized and ported to [trezor-crypto].

Range signatures xmr_gen_range_sig are CPU intensive and memory intensive operations which were originally implemented
in python (trezor-core) but it was not feasible to run on the Trezor device due to a small amount of RAM and long
computation times. It was needed to optimize the algorithm and port it to C so it is feasible to run it on the real hardware and run it fast.

Range signature is a well-contained problem with no allocations needed, simple API.
For memory and timing reasons its implemented directly in trezor-crypto (as it brings real benefit to the user).

On the other hand, MLASG and other ring signatures are built from building blocks in python for easier development,
code readability, maintenance and debugging. Porting to C is not that straightforward and I don't see any benefit here.
The memory and CPU is not the problem as in the case of range signatures so I think it is fine to have it in Python.
Porting to C would also increase complexity of trezor-crypto and could lead to bugs.

Using small and easily auditable & testable building blocks, such as ge25519_add (fast, in C) to build more complex
schemes in high level language is, in my opinion, a scalable and secure way to build the system.
Porting all Monero crypto schemes to C would be very time consuming and prone to errors.

Having access to low-level features also speeds up development of new features, such as multisigs / bulletproofs.

MLSAG may need to be slightly changed when implementing multisigs
(some preparations have been made already but we will see after this phase starts).







[trezor-crypto]: https://github.com/trezor/trezor-crypto
[trezor-core]: https://github.com/trezor/trezor-core
[monero-doc]: https://github.com/ph4r05/monero-trezor-doc
[monero-serialize]: https://github.com/ph4r05/monero-serialize
