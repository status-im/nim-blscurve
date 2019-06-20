# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.
import strutils except fromHex
import os, unittest
import nimcrypto/[sysrand, hash, sha2, utils]
import ../blscurve/milagro, ../blscurve/bls, ../blscurve/common

type
  Case01Vector = object
    domain: uint64
    message: seq[byte]
    point: ECP2_BLS381

  Case02Vector = object
    domain: uint64
    message: seq[byte]
    point: seq[byte]

  Case03Vector = object
    secretkey: seq[byte]
    publickey: seq[byte]

  Case04Vector = object
    domain: uint64
    message: seq[byte]
    secretkey: seq[byte]
    signature: seq[byte]
    sig1: seq[byte]
    sig2: seq[byte]

  Case05Vector = object

  Case06Vector = object
    signature1: seq[byte]
    signature2: seq[byte]
    signature3: seq[byte]
    asignature: seq[byte]

  Case07Vector = object
    publickey1: seq[byte]
    publickey2: seq[byte]
    publickey3: seq[byte]
    apublickey: seq[byte]

proc isEmptyLine(s: string): bool =
  if len(s) == 0:
    result = true
  else:
    for ch in s:
      if ch notin "\n\r\t ":
        if ch == '#':
          result = true
        else:
          result = false
        break

proc readVectorLine(file: File): string =
  var line: string
  while true:
    if file.readLine(line):
      if not isEmptyLine(line):
        result = line
        break
    else:
      result = ""
      break

proc openVectorFile(name: string): File =
  var filename = ""
  if existsFile(name):
    filename = name
  elif existsFile("tests" / name):
    filename = "tests" / name
  else:
    raise newException(ValueError, "File " & name & " not found!")
  result = open(filename)

proc readStrings(file: File, number: int): seq[string] =
  result = newSeq[string]()
  for i in 0..<number:
    var m = file.readVectorLine()
    if len(m) == 0:
      result.setLen(0)
      break
    else:
      result.add(m)

proc align*(buffer: seq[byte], size: int): seq[byte] =
  ## Aligns buffer ``buffer`` length to ``size``.
  ##
  ## If length of buffer ``buffer`` less then size, then result will be padded
  ## with leading zeroes.
  ## If length of buffer ``buffer`` more then size, then result will be reduced
  ## to ``size`` and some data can be lost.
  ## If length of buffer ``buffer`` equal to size, ``buffer`` will be returned
  ## as result.
  ## If length of buffer ``buffer`` is zero, then zero length result will be
  ## returned
  let length = len(buffer)
  if length > 0:
    if length == size:
      result = buffer
    elif length < size:
      let offset = size - length
      result = newSeq[byte](size)
      for i in 0..<len(buffer):
        result[offset + i] = buffer[i]
    else:
      result = buffer
      result.setLen(size)

proc parseHex[T](s: string): T =
  let length = len(s)
  let size = sizeof(T) * 2
  if length > 0:
    var i = 0
    result = cast[T](0)
    let max = if length < size: length else: size
    while i < max:
      case s[i]
      of '0'..'9':
        result = (result shl 4) or cast[T](ord(s[i]) - ord('0'))
      of 'a'..'f':
        result = (result shl 4) or cast[T](ord(s[i]) - ord('a') + 10)
      of 'A'..'F':
        result = (result shl 4) or cast[T](ord(s[i]) - ord('A') + 10)
      else:
        break
      inc(i)

proc readCase01Vector(file: File, vector: var Case01Vector): bool =
  var p: array[6, BIG_384]
  var m = file.readStrings(8)
  if len(m) == 0:
    return false
  vector.domain = parseHex[uint64](m[0])
  vector.message = fromHex(m[1])
  discard p[0].fromHex(m[2])
  discard p[1].fromHex(m[3])
  discard p[2].fromHex(m[4])
  discard p[3].fromHex(m[5])
  discard p[4].fromHex(m[6])
  discard p[5].fromHex(m[7])
  vector.point.fromBigs(p[0], p[1], p[2], p[3], p[4], p[5])
  result = true

proc readCase02Vector(file: File, vector: var Case02Vector): bool =
  var p: array[2, BIG_384]
  var m = file.readStrings(4)
  if len(m) == 0:
    return false
  var domain: int
  vector.domain = parseHex[uint64](m[0])
  vector.message = fromHex(m[1])
  vector.point = align(fromHex(m[2]), MODBYTES_384) & align(fromHex(m[3]), MODBYTES_384)
  result = true

proc readCase03Vector(file: File, vector: var Case03Vector): bool =
  var m = file.readStrings(2)
  if len(m) == 0:
    return false
  vector.secretkey = fromHex(m[0])
  vector.publickey = fromHex(m[1])
  result = true

proc readCase04Vector(file: File, vector: var Case04Vector): bool =
  var m = file.readStrings(4)
  if len(m) == 0:
    return false
  var domain: int
  vector.domain = parseHex[uint64](m[0])
  vector.message = fromHex(m[1])
  vector.secretkey = fromHex(m[2])
  vector.signature = align(fromHex(m[3]), MODBYTES_384 * 2)
  result = true

proc readCase06Vector(file: File, vector: var Case06Vector): bool =
  var m = file.readStrings(4)
  if len(m) == 0:
    return false
  vector.signature1 = align(fromHex(m[0]), MODBYTES_384 * 2)
  vector.signature2 = align(fromHex(m[1]), MODBYTES_384 * 2)
  vector.signature3 = align(fromHex(m[2]), MODBYTES_384 * 2)
  vector.asignature = align(fromHex(m[3]), MODBYTES_384 * 2)
  result = true

proc readCase07Vector(file: File, vector: var Case07Vector): bool =
  var m = file.readStrings(4)
  if len(m) == 0:
    return false
  vector.publickey1 = align(fromHex(m[0]), MODBYTES_384)
  vector.publickey2 = align(fromHex(m[1]), MODBYTES_384)
  vector.publickey3 = align(fromHex(m[2]), MODBYTES_384)
  vector.apublickey = align(fromHex(m[3]), MODBYTES_384)
  result = true

suite "Ethereum2 specification BLS381-12 test vectors suite":

  test "case01_message_hash_G2_uncompressed":
    var f = openVectorFile("case01_message_hash_G2_uncompressed.dat")
    var vector: Case01Vector
    while true:
      if not f.readCase01Vector(vector):
        break
      var ctx: sha256
      ctx.init()
      ctx.update(vector.message)
      var point = hashToG2(ctx, vector.domain)
      check point == vector.point

  test "case02_message_hash_G2_compressed":
    var f = openVectorFile("case02_message_hash_G2_compressed.dat")
    var vector: Case02Vector
    while true:
      if not f.readCase02Vector(vector):
        break
      var ctx: sha256
      ctx.init()
      ctx.update(vector.message)
      var point = hashToG2(ctx, vector.domain)
      check point.getBytes() == vector.point

  test "case03_private_to_public_key":
    var f = openVectorFile("case03_private_to_public_key.dat")
    var vector: Case03Vector
    var buffer: array[RawVerificationKeySize, byte]
    while true:
      if not f.readCase03Vector(vector):
        break
      var seckey = SigKey.init(vector.secretkey)
      var pubkey = seckey.getKey()
      var chk = pubkey.getBytes()
      check:
        pubkey.toBytes(buffer) == true
        vector.publickey == chk
        vector.publickey == buffer

  test "case04_sign_messages":
    var f = openVectorFile("case04_sign_messages.dat")
    var vector: Case04Vector
    while true:
      if not f.readCase04Vector(vector):
        break
      var seckey = SigKey.init(vector.secretkey)
      var pubkey = seckey.getKey()
      var signature = seckey.sign(vector.domain, vector.message)
      var vectsig = Signature.init(vector.signature)
      check:
        signature == vectsig
        signature.getBytes() == vector.signature

  test "case06_aggregate_sigs":
    var f = openVectorFile("case06_aggregate_sigs.dat")
    var vector: Case06Vector
    while true:
      if not f.readCase06Vector(vector):
        break
      var sig1 = Signature.init(vector.signature1)
      var sig2 = Signature.init(vector.signature2)
      var sig3 = Signature.init(vector.signature3)
      var asig = Signature.init(vector.asignature)
      var csig = combine(@[sig1, sig2, sig3])
      check:
        csig.point == asig.point
        csig.getBytes() == vector.asignature

  test "case07_aggregate_pubkeys":
    var f = openVectorFile("case07_aggregate_pubkeys.dat")
    var vector: Case07Vector
    while true:
      if not f.readCase07Vector(vector):
        break
      var key1 = VerKey.init(vector.publickey1)
      var key2 = VerKey.init(vector.publickey2)
      var key3 = VerKey.init(vector.publickey3)
      var akey = VerKey.init(vector.apublickey)
      var ckey = combine(@[key1, key2, key3])
      check:
        ckey.point == akey.point
        ckey.getBytes() == vector.apublickey
