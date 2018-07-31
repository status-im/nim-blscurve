# milagro_crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under the Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# This file may not be copied, modified, or distributed except according to those terms.

import  unittest, strutils, strformat, encodings,
        ../src/milagro_crypto

suite "Octet datatype":
  test "Creating from hex and converting to hex":

    var backend: array[64, byte]
    var x = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](backend.addr))
    let y = "1234"

    x.addr.OCT_fromHex(y[0].unsafeAddr)

    block: # Official toHex conversion
      var z1: string = ""
      z1.setLen(x.len * 2)
      x.addr.OCT_toHex(z1[0].addr)

      check: y == z1

    block: # Manual check
      check:
        x.len == 2
        x.val[0].toHex == "12"
        x.val[1].toHex == "34"

suite "CSPRNG: Cryptographically Strong Pseudo Random Number Generation":
  test "CSPRNG initialization and destruction":

    var
      rng: Csprng
      backend: array[64, byte]
      seed = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](backend.addr))
    let seedHex = "123456789ABCDEF"

    seed.addr.OCT_fromHex(seedHex[0].unsafeAddr)

    CREATE_CSPRNG(rng.addr, seed.addr)
    KILL_CSPRNG(rng.addr)

suite "Signing and verifying messages":
  test "BLS12-381":
    # https://github.com/ethereum/research/blob/051e8a9e0c04d53da293297f84eb4ea79a3e8cce/beacon_chain_impl/test.py#L9

    # (Decimal, Hex) tuple. Python supports bigint by default, Nim doesn't.
    let privkeys: array[7, tuple[decimal, hex: string]] = [
      ("1", "1"), ("5", "5"), ("124","7C"), ("735", "2DF"),
      ("127409812145", "1DAA3772B1"), ("90768492698215092512159", "133891E19CF0FC4EE59F"),
      ("0", "0")
      ]

    # Pubkey size is 2*MODBYTES_384_29+1 with MODBYTES_384_29 == 48
    type Backend = array[97, byte]

    for x in privkeys:
      echo &"          BLS12-381 testing with privkey {x.decimal}"

      # Setup boilerplate
      let
        msg_backend = x.decimal.convert("UTF-8", getCurrentEncoding())
        msg = Octet(len: cint(msg_backend.len), max: 64, val: cast[ptr UncheckedArray[byte]](msg_backend.unsafeAddr))
        seedHex = "123456789ABCDEF"

        copy_msg_backend = msg_backend

      var
        privkey_backend: Backend
        pubkey_backend: Backend
        ephemeralKey_backend: Backend
        sigPair_backend: tuple[c, d: Backend]

        privkey = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](privkey_backend.addr))
        pubkey = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](pubkey_backend.addr))
        ephemeralKey = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](ephemeralKey_backend.addr))
        sigPair: tuple[c, d: Octet]

        seed_backend: array[64, byte]
        seed = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](seed_backend.addr))
        rng: Csprng

      seed.addr.OCT_fromHex(seedHex[0].unsafeAddr)
      CREATE_CSPRNG(rng.addr, seed.addr)

      var keyWithAddr = x.hex[0]
      privkey.addr.OCT_fromHex(keyWithAddr.addr)

      sigPair.c = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](sigPair_backend.c.addr))
      sigPair.d = Octet(len: 0, max: 64, val: cast[ptr UncheckedArray[byte]](sigPair_backend.d.addr))

      # Tests
      var zeros: Backend

      echo "             Key-pair generation"
      check: # Key pair generation
        pubkey_backend == zeros
        ECP_BLS381_KEY_PAIR_GENERATE(rng.addr, privkey.addr, pubkey.addr) == EcdhError.Ok
        pubkey_backend != zeros

      echo "             Public key validity"
      check: # Validate the key
        ECP_BLS381_PUBLIC_KEY_VALIDATE(pubkey.addr) == EcdhError.Ok

      echo "             Message signing"
      check:  # Message signing
        sigPair_backend.c == zeros
        sigPair_backend.d == zeros

        ECP_BLS381_SP_DSA( # TODO: Segfaulting at the moment
          HashType.SHA256, rng.addr, ephemeralKey.addr,
          privkey.addr, msg.unsafeAddr, sigPair.c.addr, sigPair.d.addr
          ) == EcdhError.Ok
        sigPair_backend.c != zeros
        sigPair_backend.d != zeros
        msg_backend == copy_msg_backend # make sure the original message was not modified under our nose.

      echo "             Message verification"
      check:  # Message verification
        ECP_BLS381_VP_DSA(
          HashType.SHA256, pubkey.addr, msg.unsafeAddr, sigPair.c.addr, sigPair.d.addr
        ) == EcdhError.Ok
