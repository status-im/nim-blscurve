# ------------------------------------------------------------------------------------------------
# Manual edits
import std/[strutils, os]

const headerPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/../../vendor/blst/bindings/blst.h"

{.pragma: blst, importc, header: headerPath.}
{.pragma: blstheader, header: headerPath.}

type CTbool* = distinct cint
  ## Boolean for constant-time protected use-cases

type HashOrEncode* {.size: sizeof(cint).} = enum
  kEncode = 0
  kHash = 1

# Copyright Supranational LLC
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------------------------
# Generated @ 2024-07-26T17:51:41+02:00
# Command line:
#   ~/.nimble/pkgs2/nimterop-0.6.13/nimterop/toast -n -p --prefix=_ --typemap=bool=int32 -G=@\bin\b=src -G=@\bout\b=dst -o=blscurve/blst/blst_abi_candidate.nim vendor/blst/bindings/blst.h

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


{.experimental: "codeReordering".}
defineEnum(BLST_ERROR)
const
  BLST_SUCCESS* = (0).BLST_ERROR
  BLST_BAD_ENCODING* = (BLST_SUCCESS + 1).BLST_ERROR
  BLST_POINT_NOT_ON_CURVE* = (BLST_BAD_ENCODING + 1).BLST_ERROR
  BLST_POINT_NOT_IN_GROUP* = (BLST_POINT_NOT_ON_CURVE + 1).BLST_ERROR
  BLST_AGGR_TYPE_MISMATCH* = (BLST_POINT_NOT_IN_GROUP + 1).BLST_ERROR
  BLST_VERIFY_FAIL* = (BLST_AGGR_TYPE_MISMATCH + 1).BLST_ERROR
  BLST_PK_IS_INFINITY* = (BLST_VERIFY_FAIL + 1).BLST_ERROR
  BLST_BAD_SCALAR* = (BLST_PK_IS_INFINITY + 1).BLST_ERROR

# Do not importc the types that are fully defined
# otherwise they are improperly copied, for example
# when using Result or Option
# https://github.com/nim-lang/Nim/issues/9940
type
  limb_t* = uint64
  blst_scalar*  = object
    b*: array[256 div 8, byte]
  blst_fr* = object
    l*: array[256 div 8 div sizeof(limb_t), limb_t]
  blst_fp* = object
    l*: array[384 div 8 div sizeof(limb_t), limb_t]

  blst_fp2* = object
    ## 0 is "real" part, 1 is "imaginary"
    fp*: array[2, blst_fp]

  blst_fp6* = object
    fp2*: array[3, blst_fp2]

  blst_fp12* = object
    fp6*: array[2, blst_fp6]

  blst_p1* = object
    ## BLS12-381-specifc point operations.
    x*: blst_fp
    y*: blst_fp
    z*: blst_fp

  blst_p1_affine* = object
    x*: blst_fp
    y*: blst_fp

  blst_p2* = object
    x*: blst_fp2
    y*: blst_fp2
    z*: blst_fp2

  blst_p2_affine* = object
    x*: blst_fp2
    y*: blst_fp2

  cblst_scalar* {.importc: "blst_scalar", blstheader.} = object
  cblst_fr* {.importc: "blst_fr", blstheader.} = object
  cblst_fp* {.importc: "blst_fp", blstheader.} = object
  cblst_fp2* {.importc: "blst_fp2", blstheader.} = object
  cblst_fp6* {.importc: "blst_fp6", blstheader.} = object
  cblst_fp12* {.importc: "blst_fp12", blstheader.} = object
  cblst_p1* {.importc: "blst_p1", blstheader.} = object
  cblst_p1_affine* {.importc: "blst_p1_affine", blstheader.} = object
  cblst_p2* {.importc: "blst_p2", blstheader.} = object
  cblst_p2_affine* {.importc: "blst_p2_affine", blstheader.} = object
  cblst_pairing* {.importc: "blst_pairing", blstheader.} = object

template toCV*(v: untyped, t: typedesc): untyped =
  cast[ptr t](addr v)
template toCC*(v: untyped, t: typedesc): untyped =
  cast[ptr t](unsafeAddr v)

type
  AggregatedSignature {.union.} = object
    e1: blst_p1
    e2: blst_p2

  blst_pairing* = object
    # "blst_pairing" in header is defined as
    # an empty struct. This forces usage on the heap
    # through pointer.
    # We want to use the true definition in aggregate.c
    # to allow stack allocation.
    # Since the definition is private to aggregate.c
    # we have to rewrite it in Nim.
    #
    # #ifndef N_MAX
    # # define N_MAX 8
    # #endif

    # typedef union { POINTonE1 e1; POINTonE2 e2; } AggregatedSignature;
    # typedef struct {
    #     unsigned int ctrl;
    #     unsigned int nelems;
    #     const void *DST;
    #     size_t DST_len;
    #     vec384fp12 GT;
    #     AggregatedSignature AggrSign;
    #     POINTonE2_affine Q[N_MAX];
    #     POINTonE1_affine P[N_MAX];
    # } PAIRING;
    ctrl: cuint
    nelems: cuint
    DST: pointer
    DST_len: csize_t
    GT: blst_fp12
    AggrSign: AggregatedSignature
    Q: array[8, blst_p2_affine]
    P: array[8, blst_p1_affine]

var
  # Generators
  BLS12_381_G1* {.blst.}: blst_p1_affine
  BLS12_381_NEG_G1* {.blst.}: blst_p1_affine
  BLS12_381_G2* {.blst.}: blst_p2_affine
  BLS12_381_NEG_G2* {.blst.}: blst_p2_affine

{.push cdecl, importc, header: headerPath.}

proc blst_scalar_from_uint32*(dst: ptr cblst_scalar; a: array[8, uint32])
proc blst_uint32_from_scalar*(dst: var array[8, uint32]; a: ptr cblst_scalar)
proc blst_scalar_from_uint64*(dst: ptr cblst_scalar; a: array[4, uint64])
proc blst_uint64_from_scalar*(dst: var array[4, uint64]; a: ptr cblst_scalar)
proc blst_scalar_from_bendian*(dst: ptr cblst_scalar; a: array[32, byte])
proc blst_bendian_from_scalar*(dst: var array[32, byte]; a: ptr cblst_scalar)
proc blst_scalar_from_lendian*(dst: ptr cblst_scalar; a: array[32, byte])
proc blst_lendian_from_scalar*(dst: var array[32, byte]; a: ptr cblst_scalar)
proc blst_scalar_fr_check*(a: ptr cblst_scalar): CTbool
proc blst_sk_check*(a: ptr cblst_scalar): CTbool
proc blst_sk_add_n_check*(dst: ptr cblst_scalar; a: ptr cblst_scalar;
                          b: ptr cblst_scalar): CTbool
proc blst_sk_sub_n_check*(dst: ptr cblst_scalar; a: ptr cblst_scalar;
                          b: ptr cblst_scalar): CTbool
proc blst_sk_mul_n_check*(dst: ptr cblst_scalar; a: ptr cblst_scalar;
                          b: ptr cblst_scalar): CTbool
proc blst_sk_inverse*(dst: ptr cblst_scalar; a: ptr cblst_scalar)
proc blst_scalar_from_le_bytes*[T: byte|char](dst: ptr cblst_scalar;
                                              src: openArray[T]): CTbool
proc blst_scalar_from_be_bytes*[T: byte|char](dst: ptr cblst_scalar;
                                              src: openArray[T]): CTbool

# BLS12-381-specific Fr operations (Modulo curve order)
proc blst_fr_add*(ret: ptr cblst_fr; a: ptr cblst_fr; b: ptr cblst_fr)
proc blst_fr_sub*(ret: ptr cblst_fr; a: ptr cblst_fr; b: ptr cblst_fr)
proc blst_fr_mul_by_3*(ret: ptr cblst_fr; a: ptr cblst_fr)
proc blst_fr_lshift*(ret: ptr cblst_fr; a: ptr cblst_fr; count: uint)
proc blst_fr_rshift*(ret: ptr cblst_fr; a: ptr cblst_fr; count: uint)
proc blst_fr_mul*(ret: ptr cblst_fr; a: ptr cblst_fr; b: ptr cblst_fr)
proc blst_fr_sqr*(ret: ptr cblst_fr; a: ptr cblst_fr)
proc blst_fr_cneg*(ret: ptr cblst_fr; a: ptr cblst_fr; flag: bool)
proc blst_fr_eucl_inverse*(ret: ptr cblst_fr; a: ptr cblst_fr)
proc blst_fr_inverse*(ret: ptr cblst_fr; a: ptr cblst_fr)
proc blst_fr_from_uint64*(ret: ptr cblst_fr; a: array[4, uint64])
proc blst_uint64_from_fr*(ret: var array[4, uint64]; a: ptr cblst_fr)
proc blst_fr_from_scalar*(ret: ptr cblst_fr; a: ptr cblst_scalar)
proc blst_scalar_from_fr*(ret: ptr cblst_scalar; a: ptr cblst_fr)

# BLS12-381-specific Fp operations (Modulo BLS12-381 prime)
proc blst_fp_add*(ret: ptr cblst_fp; a: ptr cblst_fp; b: ptr cblst_fp)
proc blst_fp_sub*(ret: ptr cblst_fp; a: ptr cblst_fp; b: ptr cblst_fp)
proc blst_fp_mul_by_3*(ret: ptr cblst_fp; a: ptr cblst_fp)
proc blst_fp_mul_by_8*(ret: ptr cblst_fp; a: ptr cblst_fp)
proc blst_fp_lshift*(ret: ptr cblst_fp; a: ptr cblst_fp; count: uint)
proc blst_fp_mul*(ret: ptr cblst_fp; a: ptr cblst_fp; b: ptr cblst_fp)
proc blst_fp_sqr*(ret: ptr cblst_fp; a: ptr cblst_fp)
proc blst_fp_cneg*(ret: ptr cblst_fp; a: ptr cblst_fp; flag: bool)
proc blst_fp_eucl_inverse*(ret: ptr cblst_fp; a: ptr cblst_fp)
proc blst_fp_inverse*(ret: ptr cblst_fp; a: ptr cblst_fp)
proc blst_fp_sqrt*(ret: ptr cblst_fp; a: ptr cblst_fp): CTbool
proc blst_fp_from_uint32*(ret: ptr cblst_fp; a: array[12, uint32])
proc blst_uint32_from_fp*(ret: var array[12, uint32]; a: ptr cblst_fp)
proc blst_fp_from_uint64*(ret: ptr cblst_fp; a: array[6, uint64])
proc blst_uint64_from_fp*(ret: var array[6, uint64]; a: ptr cblst_fp)
proc blst_fp_from_bendian*(ret: ptr cblst_fp; a: array[48, byte])
proc blst_bendian_from_fp*(ret: var array[48, byte]; a: ptr cblst_fp)
proc blst_fp_from_lendian*(ret: ptr cblst_fp; a: array[48, byte])
proc blst_lendian_from_fp*(ret: var array[48, byte]; a: ptr cblst_fp)

# BLS12-381-specific Fp2 operations.
proc blst_fp2_add*(ret: ptr cblst_fp2; a: ptr cblst_fp2; b: ptr cblst_fp2)
proc blst_fp2_sub*(ret: ptr cblst_fp2; a: ptr cblst_fp2; b: ptr cblst_fp2)
proc blst_fp2_mul_by_3*(ret: ptr cblst_fp2; a: ptr cblst_fp2)
proc blst_fp2_mul_by_8*(ret: ptr cblst_fp2; a: ptr cblst_fp2)
proc blst_fp2_lshift*(ret: ptr cblst_fp2; a: ptr cblst_fp2; count: uint)
proc blst_fp2_mul*(ret: ptr cblst_fp2; a: ptr cblst_fp2; b: ptr cblst_fp2)
proc blst_fp2_sqr*(ret: ptr cblst_fp2; a: ptr cblst_fp2)
proc blst_fp2_cneg*(ret: ptr cblst_fp2; a: ptr cblst_fp2; flag: bool)
proc blst_fp2_eucl_inverse*(ret: ptr cblst_fp2; a: ptr cblst_fp2)
proc blst_fp2_inverse*(ret: ptr cblst_fp2; a: ptr cblst_fp2)
proc blst_fp2_sqrt*(ret: ptr cblst_fp2; a: ptr cblst_fp2): CTbool

# BLS12-381-specific Fp12 operations.
proc blst_fp12_sqr*(ret: ptr cblst_fp12; a: ptr cblst_fp12)
proc blst_fp12_cyclotomic_sqr*(ret: ptr cblst_fp12; a: ptr cblst_fp12)
proc blst_fp12_mul*(ret: ptr cblst_fp12; a: ptr cblst_fp12; b: ptr cblst_fp12)
proc blst_fp12_mul_by_xy00z0*(ret: ptr cblst_fp12; a: ptr cblst_fp12;
                              xy00z0: ptr cblst_fp6)
proc blst_fp12_conjugate*(a: ptr cblst_fp12)
proc blst_fp12_inverse*(ret: ptr cblst_fp12; a: ptr cblst_fp12)
proc blst_fp12_frobenius_map*(ret: ptr cblst_fp12; a: ptr cblst_fp12; n: uint)
  ##   caveat lector! |n| has to be non-zero and not more than 3!
proc blst_fp12_is_equal*(a: ptr cblst_fp12; b: ptr cblst_fp12): CTbool
proc blst_fp12_is_one*(a: ptr cblst_fp12): CTbool
proc blst_fp12_in_group*(a: ptr cblst_fp12): CTbool
proc blst_fp12_one*(): ptr cblst_fp12

# BLS12-381-specific G1 operations.
proc blst_p1_add*(dst: ptr cblst_p1; a: ptr cblst_p1; b: ptr cblst_p1)
proc blst_p1_add_or_double*(dst: ptr cblst_p1; a: ptr cblst_p1; b: ptr cblst_p1)
proc blst_p1_add_affine*(dst: ptr cblst_p1; a: ptr cblst_p1; b: ptr cblst_p1_affine)
proc blst_p1_add_or_double_affine*(dst: ptr cblst_p1; a: ptr cblst_p1;
                                   b: ptr cblst_p1_affine)
proc blst_p1_double*(dst: ptr cblst_p1; a: ptr cblst_p1)
proc blst_p1_mult*(dst: ptr cblst_p1; p: ptr cblst_p1;
                   scalar: ptr byte; nbits: uint)
proc blst_p1_cneg*(p: ptr cblst_p1; cbit: bool)
proc blst_p1_to_affine*(dst: ptr cblst_p1_affine; src: ptr cblst_p1)
proc blst_p1_from_affine*(dst: ptr cblst_p1; src: ptr cblst_p1_affine)
proc blst_p1_on_curve*(p: ptr cblst_p1): CTbool
proc blst_p1_in_g1*(p: ptr cblst_p1): CTbool
proc blst_p1_is_equal*(a: ptr cblst_p1; b: ptr cblst_p1): CTbool
proc blst_p1_is_inf*(a: ptr cblst_p1): CTbool
proc blst_p1_generator*(): ptr cblst_p1
proc blst_p1_affine_on_curve*(p: ptr cblst_p1_affine): CTbool
proc blst_p1_affine_in_g1*(p: ptr cblst_p1_affine): CTbool
proc blst_p1_affine_is_equal*(a: ptr cblst_p1_affine; b: ptr cblst_p1_affine): CTbool
proc blst_p1_affine_is_inf*(a: ptr cblst_p1_affine): CTbool
proc blst_p1_affine_generator*(): ptr cblst_p1_affine

# BLS12-381-specific G2 operations.
proc blst_p2_add*(dst: ptr cblst_p2; a: ptr cblst_p2; b: ptr cblst_p2)
proc blst_p2_add_or_double*(dst: ptr cblst_p2; a: ptr cblst_p2; b: ptr cblst_p2)
proc blst_p2_add_affine*(dst: ptr cblst_p2; a: ptr cblst_p2; b: ptr cblst_p2_affine)
proc blst_p2_add_or_double_affine*(dst: ptr cblst_p2; a: ptr cblst_p2;
                                   b: ptr cblst_p2_affine)
proc blst_p2_double*(dst: ptr cblst_p2; a: ptr cblst_p2)
proc blst_p2_mult*(dst: ptr cblst_p2; p: ptr cblst_p2;
                   scalar: ptr byte; nbits: uint)
proc blst_p2_cneg*(p: ptr cblst_p2; cbit: bool)
proc blst_p2_to_affine*(dst: ptr cblst_p2_affine; src: ptr cblst_p2)
proc blst_p2_from_affine*(dst: ptr cblst_p2; src: ptr cblst_p2_affine)
proc blst_p2_on_curve*(p: ptr cblst_p2): CTbool
proc blst_p2_in_g2*(p: ptr cblst_p2): CTbool
proc blst_p2_is_equal*(a: ptr cblst_p2; b: ptr cblst_p2): CTbool
proc blst_p2_is_inf*(a: ptr cblst_p2): CTbool
proc blst_p2_generator*(): ptr cblst_p2
proc blst_p2_affine_on_curve*(p: ptr cblst_p2_affine): CTbool
proc blst_p2_affine_in_g2*(p: ptr cblst_p2_affine): CTbool
proc blst_p2_affine_is_equal*(a: ptr cblst_p2_affine; b: ptr cblst_p2_affine): CTbool
proc blst_p2_affine_is_inf*(a: ptr cblst_p2_affine): CTbool
proc blst_p2_affine_generator*(): ptr cblst_p2_affine

# Multi-scalar multiplications and other multi-point operations.
proc blst_p1s_to_affine*(dst: ptr cblst_p1_affine; points: ptr ptr cblst_p1;
                         npoints: uint)
proc blst_p1s_add*(ret: ptr cblst_p1;
                   points: ptr ptr cblst_p1_affine; npoints: uint)
proc blst_p1s_mult_wbits_precompute_sizeof*(wbits: uint; npoints: uint): uint
proc blst_p1s_mult_wbits_precompute*(table: ptr cblst_p1_affine; wbits: uint;
                                     points: ptr ptr cblst_p1_affine;
                                     npoints: uint)
proc blst_p1s_mult_wbits_scratch_sizeof*(npoints: uint): uint
proc blst_p1s_mult_wbits*(ret: ptr cblst_p1; table: ptr cblst_p1_affine;
                          wbits: uint; npoints: uint;
                          scalars: ptr ptr byte; nbits: uint;
                          scratch: ptr limb_t)
proc blst_p1s_mult_pippenger_scratch_sizeof*(npoints: uint): uint
proc blst_p1s_mult_pippenger*(ret: ptr cblst_p1;
                              points: ptr ptr cblst_p1_affine; npoints: uint;
                              scalars: ptr ptr byte; nbits: uint;
                              scratch: ptr limb_t)
proc blst_p1s_tile_pippenger*(ret: ptr cblst_p1;
                              points: ptr ptr cblst_p1_affine; npoints: uint;
                              scalars: ptr ptr byte; nbits: uint;
                              scratch: ptr limb_t; bit0: uint; window: uint)
proc blst_p2s_to_affine*(dst: ptr cblst_p2_affine; points: ptr ptr cblst_p2;
                         npoints: uint)
proc blst_p2s_add*(ret: ptr cblst_p2;
                   points: ptr ptr cblst_p2_affine; npoints: uint)
proc blst_p2s_mult_wbits_precompute_sizeof*(wbits: uint; npoints: uint): uint
proc blst_p2s_mult_wbits_precompute*(table: ptr cblst_p2_affine; wbits: uint;
                                     points: ptr ptr cblst_p2_affine;
                                     npoints: uint)
proc blst_p2s_mult_wbits_scratch_sizeof*(npoints: uint): uint
proc blst_p2s_mult_wbits*(ret: ptr cblst_p2; table: ptr cblst_p2_affine;
                          wbits: uint; npoints: uint;
                          scalars: ptr ptr byte; nbits: uint;
                          scratch: ptr limb_t)
proc blst_p2s_mult_pippenger_scratch_sizeof*(npoints: uint): uint
proc blst_p2s_mult_pippenger*(ret: ptr cblst_p2;
                              points: ptr ptr cblst_p2_affine; npoints: uint;
                              scalars: ptr ptr byte; nbits: uint;
                              scratch: ptr limb_t)
proc blst_p2s_tile_pippenger*(ret: ptr cblst_p2;
                              points: ptr ptr cblst_p2_affine; npoints: uint;
                              scalars: ptr ptr byte; nbits: uint;
                              scratch: ptr limb_t; bit0: uint; window: uint)

# Hash-to-curve operations.
proc blst_map_to_g1*(dst: ptr cblst_p1; u: ptr cblst_fp; v: ptr cblst_fp)
proc blst_map_to_g2*(dst: ptr cblst_p2; u: ptr cblst_fp2; v: ptr cblst_fp2)
proc blst_encode_to_g1*[T,U,V: byte|char](dst: ptr cblst_p1;
                                          msg: openArray[T];
                                          DST: openArray[U];
                                          aug: openArray[V])
proc blst_hash_to_g1*[T,U,V: byte|char](dst: ptr cblst_p1;
                                        msg: openArray[T];
                                        DST: openArray[U];
                                        aug: openArray[V])
proc blst_encode_to_g2*[T,U,V: byte|char](dst: ptr cblst_p2;
                                          msg: openArray[T];
                                          DST: openArray[U];
                                          aug: openArray[V])
proc blst_hash_to_g2*[T,U,V: byte|char](dst: ptr cblst_p2;
                                        msg: openArray[T];
                                        DST: openArray[U];
                                        aug: openArray[V])

# Zcash-compatible serialization/deserialization.
proc blst_p1_serialize*(dst: var array[96, byte]; src: ptr cblst_p1)
proc blst_p1_compress*(dst: var array[48, byte]; src: ptr cblst_p1)
proc blst_p1_affine_serialize*(dst: var array[96, byte]; src: ptr cblst_p1_affine)
proc blst_p1_affine_compress*(dst: var array[48, byte]; src: ptr cblst_p1_affine)
proc blst_p1_uncompress*(dst: ptr cblst_p1_affine; src: array[48, byte]): BLST_ERROR
proc blst_p1_deserialize*(dst: ptr cblst_p1_affine; src: array[96, byte]): BLST_ERROR
proc blst_p2_serialize*(dst: var array[192, byte]; src: ptr cblst_p2)
proc blst_p2_compress*(dst: var array[96, byte]; src: ptr cblst_p2)
proc blst_p2_affine_serialize*(dst: var array[192, byte]; src: ptr cblst_p2_affine)
proc blst_p2_affine_compress*(dst: var array[96, byte]; src: ptr cblst_p2_affine)
proc blst_p2_uncompress*(dst: ptr cblst_p2_affine; src: array[96, byte]): BLST_ERROR
proc blst_p2_deserialize*(dst: ptr cblst_p2_affine; src: array[192, byte]): BLST_ERROR

# Specification defines two variants, 'minimal-signature-size' and
#  'minimal-pubkey-size'. To unify appearance we choose to distinguish
#  them by suffix referring to the public key type, more specifically
#  _pk_in_g1 corresponds to 'minimal-pubkey-size' and _pk_in_g2 - to
#  'minimal-signature-size'. It might appear a bit counterintuitive
#  in sign call, but no matter how you twist it, something is bound to
#  turn a little odd.

# Secret-key operations.
proc blst_keygen*[T,U: byte|char](out_SK: ptr cblst_scalar;
                                  IKM: openArray[T];
                                  info: openArray[U])
proc blst_sk_to_pk_in_g1*(out_pk: ptr cblst_p1; SK: ptr cblst_scalar)
proc blst_sign_pk_in_g1*(out_sig: ptr cblst_p2; hash: ptr cblst_p2;
                         SK: ptr cblst_scalar)
proc blst_sk_to_pk_in_g2*(out_pk: ptr cblst_p2; SK: ptr cblst_scalar)
proc blst_sign_pk_in_g2*(out_sig: ptr cblst_p1; hash: ptr cblst_p1;
                         SK: ptr cblst_scalar)

# Pairing interface.
#
#   Usage pattern on single-processor system is
#
#   blst_pairing_init(ctx, hash_or_encode, DST);
#   blst_pairing_aggregate_pk_in_g1(ctx, PK[0], aggregated_signature, msg[0]);
#   blst_pairing_aggregate_pk_in_g1(ctx, PK[1], NULL, msg[1]);
#   ...
#   blst_pairing_commit(ctx);
#   blst_pairing_finalverify(ctx, NULL);
#
#  **********************************************************************
#   Usage pattern on multi-processor system is
#
#     blst_pairing_init(pk[0], hash_or_encode, DST);
#     blst_pairing_init(pk[1], hash_or_encode, DST);
#     ...
#   start threads each processing an N/nthreads slice of PKs and messages:
#       blst_pairing_aggregate_pk_in_g1(pk[i], PK[i*n+0], NULL, msg[i*n+0]);
#       blst_pairing_aggregate_pk_in_g1(pk[i], PK[i*n+1], NULL, msg[i*n+1]);
#       ...
#       blst_pairing_commit(pkx);
#     ...
#   meanwhile in main thread
#     blst_fp12 gtsig;
#     blst_aggregated_in_g2(&gtsig, aggregated_signature);
#   join threads and merge their contexts:
#     blst_pairing_merge(pk[0], pk[1]);
#     blst_pairing_merge(pk[0], pk[2]);
#     ...
#     blst_pairing_finalverify(pk[0], gtsig);

proc blst_miller_loop*(ret: ptr cblst_fp12; Q: ptr cblst_p2_affine;
                       P: ptr cblst_p1_affine)
proc blst_miller_loop_n*(ret: ptr cblst_fp12; Qs: ptr ptr cblst_p2_affine;
                         Ps: ptr ptr cblst_p1_affine; n: uint)
proc blst_final_exp*(ret: ptr cblst_fp12; f: ptr cblst_fp12)
proc blst_precompute_lines*(Qlines: var array[68, cblst_fp6]; Q: ptr cblst_p2_affine)
proc blst_miller_loop_lines*(ret: ptr cblst_fp12; Qlines: array[68, cblst_fp6];
                             P: ptr cblst_p1_affine)
proc blst_fp12_finalverify*(gt1: ptr cblst_fp12; gt2: ptr cblst_fp12): CTbool
proc blst_pairing_sizeof*(): uint
proc blst_pairing_init*[T: byte|char](new_ctx: ptr cblst_pairing;
                                      hash_or_encode: HashOrEncode;
                                      DST: openArray[T])
proc blst_pairing_get_dst*(ctx: ptr cblst_pairing): ptr UncheckedArray[byte]
proc blst_pairing_commit*(ctx: ptr cblst_pairing)
proc blst_pairing_aggregate_pk_in_g2*[T,U: byte|char](ctx: ptr cblst_pairing;
                                                      PK: ptr cblst_p2_affine;
                                                      signature: ptr cblst_p1_affine;
                                                      msg: openArray[T];
                                                      aug: openArray[U]): BLST_ERROR
proc blst_pairing_chk_n_aggr_pk_in_g2*[T,U: byte|char](ctx: ptr cblst_pairing;
                                                       PK: ptr cblst_p2_affine;
                                                       pk_grpchk: bool;
                                                       signature: ptr cblst_p1_affine;
                                                       sig_grpchk: bool;
                                                       msg: openArray[T];
                                                       aug: openArray[U]): BLST_ERROR
proc blst_pairing_mul_n_aggregate_pk_in_g2*[T,U: byte|char](ctx: ptr cblst_pairing;
    PK: ptr cblst_p2_affine; sig: ptr cblst_p1_affine;
    scalar: ptr byte; nbits: uint;
    msg: openArray[T]; aug: openArray[U]): BLST_ERROR
proc blst_pairing_chk_n_mul_n_aggr_pk_in_g2*[T,U: byte|char](ctx: ptr cblst_pairing;
    PK: ptr cblst_p2_affine; pk_grpchk: bool; sig: ptr cblst_p1_affine;
    sig_grpchk: bool; scalar: ptr byte; nbits: uint;
    msg: openArray[T]; aug: openArray[U]): BLST_ERROR
proc blst_pairing_aggregate_pk_in_g1*[T,U: byte|char](ctx: ptr cblst_pairing;
                                                      PK: ptr cblst_p1_affine;
                                                      signature: ptr cblst_p2_affine;
                                                      msg: openArray[T];
                                                      aug: openArray[U]): BLST_ERROR
proc blst_pairing_chk_n_aggr_pk_in_g1*[T,U: byte|char](ctx: ptr cblst_pairing;
                                                       PK: ptr cblst_p1_affine;
                                                       pk_grpchk: bool;
                                                       signature: ptr cblst_p2_affine;
                                                       sig_grpchk: bool;
                                                       msg: openArray[T];
                                                       aug: openArray[U]): BLST_ERROR
proc blst_pairing_mul_n_aggregate_pk_in_g1*[T,U: byte|char](ctx: ptr cblst_pairing;
    PK: ptr cblst_p1_affine; sig: ptr cblst_p2_affine;
    scalar: ptr byte; nbits: uint;
    msg: openArray[T]; aug: openArray[U]): BLST_ERROR
proc blst_pairing_chk_n_mul_n_aggr_pk_in_g1*[T,U: byte|char](ctx: ptr cblst_pairing;
    PK: ptr cblst_p1_affine; pk_grpchk: bool; sig: ptr cblst_p2_affine;
    sig_grpchk: bool; scalar: ptr byte; nbits: uint;
    msg: openArray[T]; aug: openArray[U]): BLST_ERROR
proc blst_pairing_merge*(ctx: ptr cblst_pairing; ctx1: ptr cblst_pairing): BLST_ERROR
proc blst_pairing_finalverify*(ctx: ptr cblst_pairing; gtsig: ptr cblst_fp12): CTbool

# Customarily applications aggregate signatures separately.
#  In which case application would have to pass NULLs for |signature|
#  to blst_pairing_aggregate calls and pass aggregated signature
#  collected with these calls to blst_pairing_finalverify. Inputs are
#  Zcash-compatible "straight-from-wire" byte vectors, compressed or
#  not.
proc blst_aggregate_in_g1*(dst: ptr cblst_p1; src: ptr cblst_p1;
                           zwire: ptr byte): BLST_ERROR
proc blst_aggregate_in_g2*(dst: ptr cblst_p2; src: ptr cblst_p2;
                           zwire: ptr byte): BLST_ERROR
proc blst_aggregated_in_g1*(dst: ptr cblst_fp12; signature: ptr cblst_p1_affine)
proc blst_aggregated_in_g2*(dst: ptr cblst_fp12; signature: ptr cblst_p2_affine)

#   "One-shot" CoreVerify entry points.
proc blst_core_verify_pk_in_g1*[T,U,V: byte|char](pk: ptr cblst_p1_affine;
                                                  signature: ptr cblst_p2_affine;
                                                  hash_or_encode: HashOrEncode;
                                                  msg: openArray[T];
                                                  DST: openArray[U];
                                                  aug: openArray[V]): BLST_ERROR
proc blst_core_verify_pk_in_g2*[T,U,V: byte|char](pk: ptr cblst_p2_affine;
                                                  signature: ptr cblst_p1_affine;
                                                  hash_or_encode: HashOrEncode;
                                                  msg: openArray[T];
                                                  DST: openArray[U];
                                                  aug: openArray[V]): BLST_ERROR
{.pop.}
