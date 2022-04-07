# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import ../blscurve

# This test ensures that fake secret keys can be used for testing
# In particular this caught compiler options that miscompile BLST,
# namely -fpeel-loops -ftree-loop-vectorize
# which are unfortunately enabled at -O3

echo "\npriv_to_pub"
echo "----------------------------------\n"

proc test_sk_to_pk(seckey, pubkey: string) =

  var
    sk{.noinit.}: SecretKey
    pk{.noinit.}: PublicKey
  let ok = sk.fromHex(seckey)
  doAssert ok
  let ok2 = pk.publicFromSecret(sk)
  doAssert ok2
  doAssert pk.toHex() == pubkey, "\ncomputed: " & pk.toHex() & "\nexpected: " & pubkey & '\n'
  echo "SUCCESS"

test_sk_to_pk(
  seckey = "00000000000000000000000000000000000000000000000000000000000003e8",
  pubkey = "a60e75190e62b6a54142d147289a735c4ce11a9d997543da539a3db57def5ed83ba40b74e55065f02b35aa1d504c404b"
)

test_sk_to_pk(
  seckey = "00000000000000000000000000000000000000000000000000000000000003e9",
  pubkey = "ae12039459c60491672b6a6282355d8765ba6272387fb91a3e9604fa2a81450cf16b870bb446fc3a3e0a187fff6f8945"
)

test_sk_to_pk(
  seckey = "00000000000000000000000000000000000000000000000000000000000003ea",
  pubkey = "947b327c8a15b39634a426af70c062b50632a744eddd41b5a4686414ef4cd9746bb11d0a53c6c2ff21bbcf331e07ac92"
)

test_sk_to_pk(
  seckey = "00000000000000000000000000000000000000000000000000000000000003eb",
  pubkey = "85fc4ae543ca162474586e76d72c47d0151c3cb7b77e82c87e554abf72548e2e746bc675805b688b5016269e18ff4250"
)

test_sk_to_pk(
  seckey = "00000000000000000000000000000000000000000000000000000000000003ec",
  pubkey = "8caa0de862793e567c6050aa822db2d6cb2b520bc62b6dbcba7e773067ed09c7ba0282d7c20e01500c6c2fa76408aded"
)

# From BLST Rust test
# cargo test test_sign -- --show-output
#
# [test]
# fn test_sign() {
#     let ikm: [u8; 32] = [
#         0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
#         0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
#         0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
#         0x48, 0x99,
#     ];
#
#     let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
#     print_bytes(&sk.serialize(), "sk: ");
#     let pk = sk.sk_to_pk();
#     print_bytes(&pk.compress(), "pk: ");
#
# ---- min_pk::tests::test_sign stdout ----
# sk:  47faea55fe00a78306449165c017c9db86411a4c2467b4b89e21323c746406a0
# pk:  a18e29d0185a5a6d19edf052ae098fd2924f579b6dfb4905332b8f4fc78adeb3188ad8315bf279a144be026ac08f3441

test_sk_to_pk(
  seckey = "47faea55fe00a78306449165c017c9db86411a4c2467b4b89e21323c746406a0",
  pubkey = "a18e29d0185a5a6d19edf052ae098fd2924f579b6dfb4905332b8f4fc78adeb3188ad8315bf279a144be026ac08f3441"
)

# Ensure that secret keys with key > BLS12-381 curve order cannot be deserialized
# BLS12-381 curve order is 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

block:
  var sk{.noinit.}: SecretKey
  doAssert not sk.fromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
  doAssert not sk.fromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000002")
  echo "SUCCESS - secret keys > curve order are refused"
