# ------------------------------------------------------------------------------------------------
# Manual edits
import std/[strutils, os]

const headerPath = currentSourcePath.rsplit(DirSep, 1)[0]/".."/".."/"vendor"/"blst"/"bindings"/"blst.h"

{.pragma: blst, importc, header: headerPath.}

type CTbool* = distinct cint
type HashOrEncode* {.size: sizeof(cint).} = enum
  kEncode = 0
  kHash = 1

# Copyright Supranational LLC
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------------------------
# Generated @ 2020-07-11T15:22:46+02:00
# Command line:
#   /.../.nimble/pkgs/nimterop-0.6.2/nimterop/toast -n -p --prefix=_ --typemap=bool=int32 -G=@\bin\b=src -G=@\bout\b=dst -o=blst/blst_abi_candidate.nim vendor/blst/bindings/blst.h

# const 'bool' has unsupported value '_Bool'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}
import macros

macro defineEnum(typ: untyped): untyped =
  result = newNimNode(nnkStmtList)

  # Enum mapped to distinct cint
  result.add quote do:
    type `typ`* = distinct cint

  for i in ["+", "-", "*", "div", "mod", "shl", "shr", "or", "and", "xor", "<", "<=", "==", ">", ">="]:
    let
      ni = newIdentNode(i)
      typout = if i[0] in "<=>": newIdentNode("bool") else: typ # comparisons return bool
    if i[0] == '>': # cannot borrow `>` and `>=` from templates
      let
        nopp = if i.len == 2: newIdentNode("<=") else: newIdentNode("<")
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` = `nopp`(y, x)
        proc `ni`*(x: cint, y: `typ`): `typout` = `nopp`(y, x)
        proc `ni`*(x, y: `typ`): `typout` = `nopp`(y, x)
    else:
      result.add quote do:
        proc `ni`*(x: `typ`, y: cint): `typout` {.borrow.}
        proc `ni`*(x: cint, y: `typ`): `typout` {.borrow.}
        proc `ni`*(x, y: `typ`): `typout` {.borrow.}
    result.add quote do:
      proc `ni`*(x: `typ`, y: int): `typout` = `ni`(x, y.cint)
      proc `ni`*(x: int, y: `typ`): `typout` = `ni`(x.cint, y)

  let
    divop = newIdentNode("/")   # `/`()
    dlrop = newIdentNode("$")   # `$`()
    notop = newIdentNode("not") # `not`()
  result.add quote do:
    proc `divop`*(x, y: `typ`): `typ` = `typ`((x.float / y.float).cint)
    proc `divop`*(x: `typ`, y: cint): `typ` = `divop`(x, `typ`(y))
    proc `divop`*(x: cint, y: `typ`): `typ` = `divop`(`typ`(x), y)
    proc `divop`*(x: `typ`, y: int): `typ` = `divop`(x, y.cint)
    proc `divop`*(x: int, y: `typ`): `typ` = `divop`(x.cint, y)

    proc `dlrop`*(x: `typ`): string {.borrow.}
    proc `notop`*(x: `typ`): `typ` {.borrow.}

defineEnum(BLST_ERROR)
const
  BLST_SUCCESS* = (0).BLST_ERROR
  BLST_BAD_ENCODING* = (BLST_SUCCESS + 1).BLST_ERROR
  BLST_POINT_NOT_ON_CURVE* = (BLST_BAD_ENCODING + 1).BLST_ERROR
  BLST_POINT_NOT_IN_GROUP* = (BLST_POINT_NOT_ON_CURVE + 1).BLST_ERROR
  BLST_AGGR_TYPE_MISMATCH* = (BLST_POINT_NOT_IN_GROUP + 1).BLST_ERROR
  BLST_VERIFY_FAIL* = (BLST_AGGR_TYPE_MISMATCH + 1).BLST_ERROR

type
  limb_t* {.blst.} = uint64
  blst_scalar* {.byref, blst.} = object
    l*: array[typeof(256)(typeof(256)(256 / typeof(256)(8)) /
        typeof(256)(sizeof((limb_t)))), limb_t]
  blst_fr* {.byref, blst.} = object
    l*: array[typeof(256)(typeof(256)(256 / typeof(256)(8)) /
        typeof(256)(sizeof((limb_t)))), limb_t]
  blst_fp* {.byref, blst.} = object
    ## 0 is "real" part, 1 is "imaginary"
    l*: array[typeof(384)(typeof(384)(384 / typeof(384)(8)) /
        typeof(384)(sizeof((limb_t)))), limb_t]

  blst_fp2* {.byref, blst.} = object
    ## 0 is "real" part, 1 is "imaginary"
    fp*: array[2, blst_fp]

  blst_fp6* {.byref, blst.} = object
    fp2*: array[3, blst_fp2]

  blst_fp12* {.byref, blst.} = object
    fp6*: array[2, blst_fp6]

  blst_p1* {.byref, blst.} = object
    ## BLS12-381-specifc point operations.
    x*: blst_fp
    y*: blst_fp
    z*: blst_fp

  blst_p1_affine* {.byref, blst.} = object
    x*: blst_fp
    y*: blst_fp

  blst_p2* {.byref, blst.} = object
    x*: blst_fp2
    y*: blst_fp2
    z*: blst_fp2

  blst_p2_affine* {.byref, blst.} = object
    x*: blst_fp2
    y*: blst_fp2

  blst_pairing* {.incompleteStruct, blst.} = object

var
  # Generators
  BLS12_381_G1* {.blst.}: blst_p1_affine
  BLS12_381_NEG_G1* {.blst.}: blst_p1_affine
  BLS12_381_G2* {.blst.}: blst_p2_affine
  BLS12_381_NEG_G2* {.blst.}: blst_p2_affine

{.push cdecl, importc, header: headerPath.}

proc blst_scalar_from_uint32*(ret: var blst_scalar; a: array[8, uint32])
proc blst_uint32_from_scalar*(ret: var array[8, uint32]; a: blst_scalar)
proc blst_scalar_from_uint64*(ret: var blst_scalar; a: array[4, uint64])
proc blst_uint64_from_scalar*(ret: var array[4, uint64]; a: blst_scalar)
proc blst_scalar_from_bendian*(ret: var blst_scalar; a: array[32, byte])
proc blst_bendian_from_scalar*(ret: var array[32, byte]; a: blst_scalar)
proc blst_scalar_from_lendian*(ret: var blst_scalar; a: array[32, byte])
proc blst_lendian_from_scalar*(ret: var array[32, byte]; a: blst_scalar)
proc blst_scalar_fr_check*(a: blst_scalar): CTBool

# BLS12-381-specific Fr operations (Modulo curve order)
proc blst_fr_add*(ret: var blst_fr; a: blst_fr; b: blst_fr)
proc blst_fr_sub*(ret: var blst_fr; a: blst_fr; b: blst_fr)
proc blst_fr_mul_by_3*(ret: var blst_fr; a: blst_fr)
proc blst_fr_lshift*(ret: var blst_fr; a: blst_fr; count: uint)
proc blst_fr_rshift*(ret: var blst_fr; a: blst_fr; count: uint)
proc blst_fr_mul*(ret: var blst_fr; a: blst_fr; b: blst_fr)
proc blst_fr_sqr*(ret: var blst_fr; a: blst_fr)
proc blst_fr_cneg*(ret: var blst_fr; a: blst_fr; flag: uint)
proc blst_fr_to*(ret: var blst_fr; a: blst_fr)
proc blst_fr_from*(ret: var blst_fr; a: blst_fr)

# BLS12-381-specific Fp operations (Modulo BLS12-381 prime)
proc blst_fp_add*(ret: var blst_fp; a: blst_fp; b: blst_fp)
proc blst_fp_sub*(ret: var blst_fp; a: blst_fp; b: blst_fp)
proc blst_fp_mul_by_3*(ret: var blst_fp; a: blst_fp)
proc blst_fp_mul_by_8*(ret: var blst_fp; a: blst_fp)
proc blst_fp_lshift*(ret: var blst_fp; a: blst_fp; count: uint)
proc blst_fp_mul*(ret: var blst_fp; a: blst_fp; b: blst_fp)
proc blst_fp_sqr*(ret: var blst_fp; a: blst_fp)
proc blst_fp_cneg*(ret: var blst_fp; a: blst_fp; flag: uint)
proc blst_fp_eucl_inverse*(ret: var blst_fp; a: blst_fp)
proc blst_fp_to*(ret: var blst_fp; a: blst_fp)
proc blst_fp_from*(ret: var blst_fp; a: blst_fp)
proc blst_fp_from_uint32*(ret: var blst_fp; a: array[12, uint32])
proc blst_uint32_from_fp*(ret: var array[12, uint32]; a: blst_fp)
proc blst_fp_from_uint64*(ret: var blst_fp; a: array[6, uint64])
proc blst_uint64_from_fp*(ret: var array[6, uint64]; a: blst_fp)
proc blst_fp_from_bendian*(ret: var blst_fp; a: array[48, byte])
proc blst_bendian_from_fp*(ret: var array[48, byte]; a: blst_fp)
proc blst_fp_from_lendian*(ret: var blst_fp; a: array[48, byte])
proc blst_lendian_from_fp*(ret: var array[48, byte]; a: blst_fp)

# BLS12-381-specific Fp2 operations.
proc blst_fp2_add*(ret: var blst_fp2; a: blst_fp2; b: blst_fp2)
proc blst_fp2_sub*(ret: var blst_fp2; a: blst_fp2; b: blst_fp2)
proc blst_fp2_mul_by_3*(ret: var blst_fp2; a: blst_fp2)
proc blst_fp2_mul_by_8*(ret: var blst_fp2; a: blst_fp2)
proc blst_fp2_lshift*(ret: var blst_fp2; a: blst_fp2; count: uint)
proc blst_fp2_mul*(ret: var blst_fp2; a: blst_fp2; b: blst_fp2)
proc blst_fp2_sqr*(ret: var blst_fp2; a: blst_fp2)
proc blst_fp2_cneg*(ret: var blst_fp2; a: blst_fp2; flag: uint)

# BLS12-381-specific Fp12 operations.
proc blst_fp12_sqr*(ret: var blst_fp12; a: blst_fp12)
proc blst_fp12_cyclotomic_sqr*(ret: var blst_fp12; a: blst_fp12)
proc blst_fp12_mul*(ret: var blst_fp12; a: blst_fp12; b: blst_fp12)
proc blst_fp12_mul_by_xy00z0*(ret: var blst_fp12; a: blst_fp12; xy00z0: blst_fp6)
proc blst_fp12_conjugate*(a: var blst_fp12)
proc blst_fp12_inverse*(ret: var blst_fp12; a: blst_fp12)
proc blst_fp12_frobenius_map*(ret: var blst_fp12; a: blst_fp12; n: uint)
  ##   caveat lector! |n| has to be non-zero and not more than 3!
proc blst_fp12_is_equal*(a: blst_fp12; b: blst_fp12): CTBool
proc blst_fp12_is_one*(a: blst_fp12): CTBool
proc blst_p1_add*(dst: var blst_p1; a: blst_p1; b: blst_p1)
proc blst_p1_add_or_double*(dst: var blst_p1; a: blst_p1; b: blst_p1)
proc blst_p1_add_affine*(dst: var blst_p1; a: blst_p1; b: blst_p1_affine)
proc blst_p1_add_or_double_affine*(dst: var blst_p1; a: blst_p1; b: blst_p1_affine)
proc blst_p1_double*(dst: var blst_p1; a: blst_p1)
proc blst_p1_mult_w5*(dst: var blst_p1; p: blst_p1; scalar: blst_scalar; nbits: uint)
proc blst_p1_cneg*(p: var blst_p1; cbit: uint)
proc blst_p1_to_affine*(dst: var blst_p1_affine; src: blst_p1)
proc blst_p1_from_affine*(dst: var blst_p1; src: blst_p1_affine)
proc blst_p1_affine_on_curve*(p: blst_p1_affine): CTBool
proc blst_p1_affine_in_g1*(p: blst_p1_affine): CTBool
proc blst_p1_affine_is_equal*(a: blst_p1_affine; b: blst_p1_affine): CTBool
proc blst_p2_add*(dst: var blst_p2; a: blst_p2; b: blst_p2)
proc blst_p2_add_or_double*(dst: var blst_p2; a: blst_p2; b: blst_p2)
proc blst_p2_add_affine*(dst: var blst_p2; a: blst_p2; b: blst_p2_affine)
proc blst_p2_add_or_double_affine*(dst: var blst_p2; a: blst_p2; b: blst_p2_affine)
proc blst_p2_double*(dst: var blst_p2; a: blst_p2)
proc blst_p2_mult_w5*(dst: var blst_p2; p: blst_p2; scalar: blst_scalar; nbits: uint)
proc blst_p2_cneg*(p: var blst_p2; cbit: uint)
proc blst_p2_to_affine*(dst: var blst_p2_affine; src: blst_p2)
proc blst_p2_from_affine*(dst: var blst_p2; src: blst_p2_affine)
proc blst_p2_affine_on_curve*(p: blst_p2_affine): CTBool
proc blst_p2_affine_in_g2*(p: blst_p2_affine): CTBool
proc blst_p2_affine_is_equal*(a: blst_p2_affine; b: blst_p2_affine): CTBool

# Hash-to-curve operations.
proc blst_map_to_g1*(dst: var blst_p1; u: blst_fp; v: blst_fp)
proc blst_map_to_g2*(dst: var blst_p2; u: blst_fp2; v: blst_fp2)
proc blst_encode_to_g1*[T,U,V: byte|char](dst: var blst_p1;
                       msg: openArray[T];
                       domainSepTag: openArray[U];
                       aug: openArray[V])
proc blst_hash_to_g1*[T,U,V: byte|char](dst: var blst_p1;
                       msg: openArray[T];
                       domainSepTag: openArray[U];
                       aug: openArray[V])
proc blst_encode_to_g2*[T,U,V: byte|char](dst: var blst_p2;
                       msg: openArray[T];
                       domainSepTag: openArray[U];
                       aug: openArray[V])
proc blst_hash_to_g2*[T,U,V: byte|char](dst: var blst_p2;
                       msg: openArray[T];
                       domainSepTag: openArray[U];
                       aug: openArray[V])

# Zcash-compatible serialization/deserialization.
proc blst_p1_serialize*(dst: var array[96, byte]; src: blst_p1)
proc blst_p1_compress*(dst: var array[48, byte]; src: blst_p1)
proc blst_p1_affine_serialize*(dst: var array[96, byte]; src: blst_p1_affine)
proc blst_p1_affine_compress*(dst: var array[48, byte]; src: blst_p1_affine)
proc blst_p1_uncompress*(dst: var blst_p1_affine; src: array[48, byte]): BLST_ERROR
proc blst_p1_deserialize*(dst: var blst_p1_affine; src: array[96, byte]): BLST_ERROR
proc blst_p2_serialize*(dst: var array[192, byte]; src: blst_p2)
proc blst_p2_compress*(dst: var array[96, byte]; src: blst_p2)
proc blst_p2_affine_serialize*(dst: var array[192, byte]; src: blst_p2_affine)
proc blst_p2_affine_compress*(dst: var array[96, byte]; src: blst_p2_affine)
proc blst_p2_uncompress*(dst: var blst_p2_affine; src: array[96, byte]): BLST_ERROR
proc blst_p2_deserialize*(dst: var blst_p2_affine; src: array[192, byte]): BLST_ERROR
proc blst_keygen*[T,U: byte|char](out_SK: var blst_scalar; IKM: openArray[T]; info: openArray[U])

# Specification defines two variants, 'minimal-signature-size' and
#  'minimal-pubkey-size'. To unify appearance we choose to distinguish
#  them by suffix referring to the public key type, more specifically
#  _pk_in_g1 corresponds to 'minimal-pubkey-size' and _pk_in_g2 - to
#  'minimal-signature-size'. It might appear a bit counterintuitive
#  in sign call, but no matter how you twist it, something is bound to
#  turn a little odd.

# Secret-key operations.
proc blst_sk_to_pk_in_g1*(out_pk: var blst_p1; SK: blst_scalar)
proc blst_sign_pk_in_g1*(out_sig: var blst_p2; hash: blst_p2; SK: blst_scalar)
proc blst_sk_to_pk_in_g2*(out_pk: var blst_p2; SK: blst_scalar)
proc blst_sign_pk_in_g2*(out_sig: var blst_p1; hash: blst_p1; SK: blst_scalar)

# Pairing interface
#
#  Usage pattern on single-processor system is
#
#  blst_pairing_init(ctx);
#  blst_pairing_aggregate_pk_in_g1(ctx, PK1, aggregated_signature, message1);
#  blst_pairing_aggregate_pk_in_g1(ctx, PK2, NULL, message2);
#  ...
#  blst_pairing_commit(ctx);
#  blst_pairing_finalverify(ctx, NULL);
#
# **********************************************************************
#  Usage pattern on multi-processor system is
#
#    blst_pairing_init(pk0);
#    blst_pairing_init(pk1);
#    ...
#  start threads each processing a slice of PKs and messages:
#      blst_pairing_aggregate_pk_in_g1(pkx, PK[], NULL, message[]);
#      blst_pairing_commit(pkx);
#    ...
#    blst_fp12 gtsig;
#    blst_aggregated_in_g2(&gtsig, aggregated_signature);
#  join threads and merge their contexts:
#    blst_pairing_merge(pk0, pk1);
#    blst_pairing_merge(pk0, pk2);
#    ...
#    blst_pairing_finalverify(pk0, gtsig);
#

proc blst_miller_loop*(ret: var blst_fp12; Q: blst_p2_affine; P: blst_p1_affine)
proc blst_final_exp*(ret: var blst_fp12; f: blst_fp12)
proc blst_precompute_lines*(Qlines: var array[68, blst_fp6]; Q: blst_p2_affine)
proc blst_miller_loop_lines*(ret: var blst_fp12; Qlines: array[68, blst_fp6]; P: blst_p1_affine)
proc blst_pairing_sizeof*(): uint
proc blst_pairing_init*(new_ctx: var blst_pairing)
proc blst_pairing_commit*(ctx: var blst_pairing)
proc blst_pairing_aggregate_pk_in_g2*[T,U,V: byte|char](
                                     ctx: var blst_pairing; PK: ptr blst_p2_affine;
                                     signature: ptr blst_p1_affine;
                                     hash_or_encode: HashOrEncode;
                                     msg: openArray[T];
                                     domainSepTag: openArray[U];
                                     aug: openArray[V]): BLST_ERROR
proc blst_pairing_mul_n_aggregate_pk_in_g2*(ctx: var blst_pairing;
    PK: ptr blst_p2_affine; sig: ptr blst_p1_affine; hash: blst_p1_affine;
    scalar: limb_t; nbits: uint): BLST_ERROR
proc blst_pairing_aggregate_pk_in_g1*[T,U,V: byte|char](
                                     ctx: var blst_pairing; PK: ptr blst_p1_affine;
                                     signature: ptr blst_p2_affine;
                                     hash_or_encode: HashOrEncode;
                                     msg: openArray[T];
                                     domainSepTag: openArray[U];
                                     aug: openArray[V]): BLST_ERROR
proc blst_pairing_mul_n_aggregate_pk_in_g1*(ctx: var blst_pairing;
    PK: ptr blst_p1_affine; sig: ptr blst_p2_affine; hash: blst_p2_affine;
    scalar: limb_t; nbits: uint): BLST_ERROR
proc blst_pairing_merge*(ctx: var blst_pairing; ctx1: blst_pairing): BLST_ERROR
proc blst_pairing_finalverify*(ctx: var blst_pairing; gtsig: ptr blst_fp12): CTBool

#   Customarily applications aggregate signatures separately.
#    In which case application would have to pass NULLs for |signature|
#    to blst_pairing_aggregate calls and pass aggregated signature
#    collected with these calls to blst_pairing_finalverify. Inputs are
#    Zcash-compatible "straight-from-wire" byte vectors, compressed or
#    not.
proc blst_aggregate_in_g1*(dst: var blst_p1; src: blst_p1; zwire: ptr byte): BLST_ERROR
proc blst_aggregate_in_g2*(dst: var blst_p2; src: blst_p2; zwire: ptr byte): BLST_ERROR
proc blst_aggregated_in_g1*(dst: var blst_fp12; signature: blst_p1_affine)
proc blst_aggregated_in_g2*(dst: var blst_fp12; signature: blst_p2_affine)

#   "One-shot" CoreVerify entry points.
proc blst_core_verify_pk_in_g1*[T,U,V: byte|char](pk: blst_p1_affine;
                               signature: blst_p2_affine;
                               hash_or_encode: HashOrEncode;
                               msg: openArray[T];
                               domainSepTag: openArray[U];
                               aug: openArray[V]): BLST_ERROR
proc blst_core_verify_pk_in_g2*[T,U,V: byte|char](pk: blst_p2_affine;
                               signature: blst_p1_affine;
                               hash_or_encode: HashOrEncode;
                               msg: openArray[T];
                               domainSepTag: openArray[U];
                               aug: openArray[V]): BLST_ERROR
{.pop.}
