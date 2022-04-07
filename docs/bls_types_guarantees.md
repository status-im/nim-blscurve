# BLS types guarantees

This document outlines the assumptions when working with BLS curves types.

## Secret Keys / private keys.

Spec: 0 < SK < r (BLS12-381 curve order)

**On creation via:**
- Lamport key (EIP2333): `derive_master_secretKey` or `derive_child_secretKey`
- `keyGen`

An internal procedure `hkdf_mod_r` guarantees that the secret keys is below the BLS12-381 curve order

**On deserialization via:**
- `fromBytes` and `fromHex`

The input is checked for `0 < SK < r` with both BLST and Miracl backend.

There is no other public API to create a SecretKey instance.

## Public keys

Spec: PK != infinity point & PK in G1 subgroup

**On creation via:**
- `publicFromSecret`

Given a secret key `0 < SK < r`, and the generator point G, we have the scalar multiplication \[SK\]G != infinity and in the G1 subgroup.

Note: `publicFromSecret` rechecks the `0 < SK < r` guaranteed by the `SecretKey` type internally.

**On deserialization via:**
- `fromBytes` and `fromHex`

The input is checked against both conditions with both BLST and MIRACL backend.
- Procedures in `bls_sig_io.nim`:
  - `fromBytes` and `fromHex`
- BLST: `blst_p1_affine_is_inf` and subgroup checks `blst_p1_affine_in_g1`
- MIRACL: `isinf` and `subgroupCheck`

There is no other public API to create a PublicKey instance.
