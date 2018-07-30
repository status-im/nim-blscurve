# milagro_crypto
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under the Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# This file may not be copied, modified, or distributed except according to those terms.

import  unittest, strutils,
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





