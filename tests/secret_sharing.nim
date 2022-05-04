# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  std/[unittest, sequtils],
  stew/endians2,
    # Public API
  ../blscurve

template wrappedTest(desc: string, body: untyped): untyped =
  ## Wrap test in a proc to avoid having globals everywhere
  ## ballooning the test BSS space usage
  ## properly test destructors/GC/try-finally, ...
  ## aliasing
  ## and optimizations (that don't apply to globals)
  test desc:
    proc wTest() =
      body
    wTest()

type
  SecretShare = object
    secret: SecretKey
    id: ID

  SignsShare = object
    sign: Signature
    id: ID

proc keyGen(seed: uint64): tuple[pubkey: PublicKey, seckey: SecretKey] =
  var ikm: array[32, byte]
  ikm[0 ..< 8] = seed.toBytesLE
  let ok = ikm.keyGen(result.pubkey, result.seckey)
  doAssert ok

proc blsIdFromUint32(x: uint32) : ID =
  var a: array[8, uint32] = [uint32 0, 0, 0, 0, 0, 0, 0, x]
  ID.fromUint32(a)

proc generateSecretShares(sk: SecretKey, k: int, n: int): seq[SecretShare] =
  doAssert k <= n
  var originPts: seq[SecretKey]
  originPts.add(sk)
  for i in 1 ..< k:
    originPts.add(keyGen(uint64(42 + i)).seckey)

  for i in uint32(0) ..< uint32(n):
    # id must not be zero
    let id = blsIdFromUint32(i + 1)
    let secret = genSecretShare(originPts, id)
    result.add(SecretShare(secret: secret, id: id))

proc rekeySecretShares(shares: openArray[SecretShare], k: int): seq[SecretShare] =
  doAssert k <= shares.len
  var originPts: seq[SecretKey]
  # generates a new random polynomial with constant term zero
  # Note: The polynomial must be from the same degree as the original one
  originPts.add(SecretKey())
  for i in 1 ..< k:
    originPts.add(keyGen(uint64(42 + i * 21)).seckey)

  for old in shares:
    let secret = genSecretShare(originPts, old.id)
    let newSecret = add(old.secret, secret)
    result.add(SecretShare(secret: newSecret, id: old.id))

proc secrets(shares: openArray[SecretShare]): seq[SecretKey] =
  shares.mapIt(it.secret)

proc ids(shares: openArray[SecretShare]): seq[ID] =
  shares.mapIt(it.id)

proc signs(shares: openArray[SignsShare]): seq[Signature] =
  shares.mapIt(it.sign)

proc ids(shares: openArray[SignsShare]): seq[ID] =
  shares.mapIt(it.id)

proc sign(shares: openArray[SecretShare], data: openArray[byte]): seq[SignsShare] =
  for share in items(shares):
    result.add(SignsShare(sign: share.secret.sign(data), id: share.id))

proc testKeyRecover(origin: SecretKey, shares: openArray[SecretShare]) =
  let k = recover(shares.secrets, shares.ids).expect("valid shares")
  doAssert origin.toHex() == k.toHex()

proc testFailKeyRecover(origin: SecretKey, shares: openArray[SecretShare]) =
  doAssert recover(shares.secrets, shares.ids).isErr

proc testWrongKeyRecovery(origin: SecretKey, shares: openArray[SecretShare]) =
  let k = recover(shares.secrets, shares.ids).expect("valid shares")
  doAssert not (origin.toHex() == k.toHex())

proc testSignRecover(pk: PublicKey,
                     msg: array[8, byte],
                     shares: openArray[SignsShare]) =
  let s = recover(shares.signs, shares.ids).expect("valid shares")
  doAssert pk.verify(msg, s)

proc testFailSignRecover(pk: PublicKey, msg: array[8, byte], shares: openArray[SignsShare]) =
  let s = recover(shares.signs, shares.ids).expect("valid shares")
  doAssert not pk.verify(msg, s)

suite "Shamir's Secret Sharing":
  var sk: SecretKey
  discard sk.fromHex("1b500388741efd98239a9b3a689721a89a92e8b209aabb10fb7dc3f844976dc2")

  var pk: PublicKey
  discard pk.publicFromSecret(sk)

  var msg: array[8, byte] = [byte 0,1,2,3,4,5,6,7]
  var pts: array[2, SecretKey] = [sk, keyGen(84)[1]]

  wrappedTest "secret keys reconsturction 0/0":
    let shares = generateSecretShares(sk, 0, 0)
    check len(shares) == 0

  wrappedTest "secret keys reconsturction 1/1":
    let shares = generateSecretShares(sk, 1, 1)
    check len(shares) == 1
    check shares[0].secret.toHex() == sk.toHex()
    testKeyRecover(sk, shares)

  wrappedTest "secret keys reconsturction n/n":
    let n = 3
    let k = n
    let shares = generateSecretShares(sk, k, n)
    check len(shares) == n

    for k in items(shares.secrets):
      check not (k.toHex() == sk.toHex())

    testKeyRecover(sk, shares)

    testWrongKeyRecovery(sk, [shares[0], shares[1]])
    testWrongKeyRecovery(sk, [shares[0], shares[2]])
    testWrongKeyRecovery(sk, [shares[1], shares[2]])
    testFailKeyRecover(sk, [shares[0], shares[1], shares[1]])


  wrappedTest "secret keys reconsturction k/n":
    const n = 3
    const k = 2
    let shares = generateSecretShares(sk, k, n)
    check len(shares) == n

    testKeyRecover(sk, [shares[0], shares[1]])
    testKeyRecover(sk, [shares[0], shares[2]])
    testKeyRecover(sk, [shares[1], shares[2]])

    testKeyRecover(sk, shares)

    testWrongKeyRecovery(sk, [shares[0]])
    testWrongKeyRecovery(sk, [shares[1]])
    testWrongKeyRecovery(sk, [shares[2]])

  wrappedTest "signatures reconstuction 1/1":
    let shares = generateSecretShares(sk, 1, 1)
    let signs = shares.sign(msg)
    check len(signs) == 1
    check sk.sign(msg) == signs[0].sign
    testSignRecover(pk, msg, signs)

  wrappedTest "signatures reconstuction n/n":
    const n = 3
    const k = n

    let shares = generateSecretShares(sk, k, n)
    check len(shares) == n

    let signs = shares.sign(msg)

    testSignRecover(pk, msg, signs)

    testFailSignRecover(pk, msg, [signs[0], signs[1]])
    testFailSignRecover(pk, msg, [signs[0], signs[2]])
    testFailSignRecover(pk, msg, [signs[1], signs[2]])

  wrappedTest "signatures reconstuction k/n":
    const n = 3
    const k = 2

    let shares = generateSecretShares(sk, k, n)
    check len(shares) == n

    let signs = shares.sign(msg)

    testSignRecover(pk, msg, [signs[0], signs[1]])
    testSignRecover(pk, msg, [signs[0], signs[2]])
    testSignRecover(pk, msg, [signs[1], signs[2]])

    testSignRecover(pk, msg, signs)
    testSignRecover(pk, msg, [signs[2], signs[1], signs[0]])

    testFailSignRecover(pk, msg, [signs[0]])
    testFailSignRecover(pk, msg, [signs[1]])
    testFailSignRecover(pk, msg, [signs[2]])

  wrappedTest "rekeying k/n":
    const n = 3
    const k = 2

    let shares = generateSecretShares(sk, k, n)
    check len(shares) == n

    let signs = shares.sign(msg)

    testSignRecover(pk, msg, signs)

    let newShares = rekeySecretShares(shares, k)

    check len(newShares) == n

    let newSigns = newShares.sign(msg)
    testSignRecover(pk, msg, newSigns)
