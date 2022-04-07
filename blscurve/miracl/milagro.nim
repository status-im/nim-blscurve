# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Milagro should be compiled for C99.
# This statement checks to see if we're using a backend other then C,
# and if not, passes C99.
# We would just check for C except Nim only defines the other backends.

{.push raises: [].} # C functions don't raise

when not defined(cpp) or defined(objc) or defined(js):
  {.passc: "-std=c99".}

import strutils
from os import DirSep

when (sizeof(int) == 4) or defined(use32):
  const milagroPath = currentSourcePath.rsplit(DirSep, 1)[0] & DirSep &
                        "csources" & DirSep & "32" & DirSep

  {.pragma: milagro_func, importc, cdecl.}

  ## Compile required dependencies
  {.compile: milagroPath & "oct.c"}
  {.compile: milagroPath & "big_384_29.c"}
  {.compile: milagroPath & "ecp_BLS12381.c"}
  {.compile: milagroPath & "ecp2_BLS12381.c"}
  {.compile: milagroPath & "fp_BLS12381.c"}
  {.compile: milagroPath & "fp2_BLS12381.c"}
  {.compile: milagroPath & "fp4_BLS12381.c"}
  {.compile: milagroPath & "fp12_BLS12381.c"}
  {.compile: milagroPath & "pair_BLS12381.c"}
  {.compile: milagroPath & "rom_curve_BLS12381.c"}
  {.compile: milagroPath & "rom_field_BLS12381.c"}

  type
    Chunk* = int32
    Sign32* = int32

  const
    MODBYTES_384* = 48 # config_big_384_29.h
    BASEBITS_384* = 29 # config_big_384_29.h

elif sizeof(int) == 8:
  const milagroPath = currentSourcePath.rsplit(DirSep, 1)[0] & DirSep &
                      "csources" & DirSep & "64" & DirSep

  {.pragma: milagro_func, importc, cdecl.}

  ## Compile required dependencies
  {.compile: milagroPath & "oct.c"}
  {.compile: milagroPath & "big_384_58.c"}
  {.compile: milagroPath & "ecp_BLS12381.c"}
  {.compile: milagroPath & "ecp2_BLS12381.c"}
  {.compile: milagroPath & "fp_BLS12381.c"}
  {.compile: milagroPath & "fp2_BLS12381.c"}
  {.compile: milagroPath & "fp4_BLS12381.c"}
  {.compile: milagroPath & "fp12_BLS12381.c"}
  {.compile: milagroPath & "pair_BLS12381.c"}
  {.compile: milagroPath & "rom_curve_BLS12381.c"}
  {.compile: milagroPath & "rom_field_BLS12381.c"}

  type
    Chunk* = int64
    Sign32* = int32

  const
    MODBYTES_384* = 48 # config_big_384_58.h
    BASEBITS_384* = 58 # config_big_384_58.h

const
  BIGBITS_384* = 8 * MODBYTES_384
  NLEN_384* = (1 + ((8 * MODBYTES_384 - 1) div BASEBITS_384))
  DNLEN_384* = 2 * NLEN_384

type
  BIG_384* = array[NLEN_384, Chunk]
  DBIG_384* = array[DNLEN_384, Chunk]

  FP_BLS12381* = object
    g*: BIG_384
    xes*: Sign32

  FP2_BLS12381* = object
    a*: FP_BLS12381
    b*: FP_BLS12381

  FP4_BLS12381* = object
    a*: FP2_BLS12381
    b*: FP2_BLS12381

  FP12_BLS12381* = object
    a*: FP4_BLS12381
    b*: FP4_BLS12381
    c*: FP4_BLS12381
    t*: cint

  ECP_BLS12381* = object
    x*: FP_BLS12381
    y*: FP_BLS12381
    z*: FP_BLS12381

  ECP2_BLS12381* = object
    x*: FP2_BLS12381
    y*: FP2_BLS12381
    z*: FP2_BLS12381

  GroupG1* = ECP_BLS12381
  GroupG2* = ECP2_BLS12381

when (sizeof(int) == 4) or defined(use32):
  proc BIG_384_toBytes*(b: ptr char, a: BIG_384) {.
       importc: "BIG_384_29_toBytes", cdecl.}
  proc BIG_384_output*(a: BIG_384) {.
       importc: "BIG_384_29_output", cdecl.}
  proc BIG_384_comp*(a: BIG_384, b: BIG_384): cint {.
       importc: "BIG_384_29_comp", cdecl.}
  proc BIG_384_nbits*(a: BIG_384): cint {.
       importc: "BIG_384_29_nbits", cdecl.}
  proc BIG_384_shr*(a: BIG_384, k: cint) {.
       importc: "BIG_384_29_shr", cdecl.}
  proc BIG_384_shl*(a: BIG_384, s: cint) {.
       importc: "BIG_384_29_shl", cdecl.}
  proc BIG_384_fshr*(a: BIG_384, s: cint): cint {.
       importc: "BIG_384_29_fshr", cdecl.}
  proc BIG_384_fshl*(a: BIG_384, s: cint): cint {.
       importc: "BIG_384_29_fshl", cdecl.}
  proc BIG_384_dshl*(x: DBIG_384, s: cint) {.
       importc: "BIG_384_29_dshl", cdecl.}
  proc BIG_384_dmod*(x: BIG_384, y: DBIG_384, n: BIG_384) {.
       importc: "BIG_384_29_dmod", cdecl.}
  proc BIG_384_copy*(a: BIG_384, b: BIG_384) {.
       importc: "BIG_384_29_copy", cdecl.}
  proc BIG_384_norm*(a: BIG_384): Chunk {.
       importc: "BIG_384_29_norm", cdecl.}
  proc BIG_384_parity*(a: BIG_384): cint {.
       importc: "BIG_384_29_parity", cdecl.}
  proc BIG_384_jacobi*(a, p: BIG_384): cint {.
       importc: "BIG_384_29_jacobi", cdecl.}
  proc BIG_384_rcopy*(b, a: BIG_384) {.
       importc: "BIG_384_29_rcopy", cdecl.}
  proc BIG_384_mod*(x, n: BIG_384) {.
       importc: "BIG_384_29_mod", cdecl.}
  proc BIG_384_iszilch*(x: BIG_384): cint {.
       importc: "BIG_384_29_iszilch", cdecl.}
elif sizeof(int) == 8:
  proc BIG_384_toBytes*(b: ptr char, a: BIG_384) {.
       importc: "BIG_384_58_toBytes", cdecl.}
  proc BIG_384_output*(a: BIG_384) {.
       importc: "BIG_384_58_output", cdecl.}
  proc BIG_384_comp*(a: BIG_384, b: BIG_384): cint {.
       importc: "BIG_384_58_comp", cdecl.}
  proc BIG_384_nbits*(a: BIG_384): cint {.
       importc: "BIG_384_58_nbits", cdecl.}
  proc BIG_384_shr*(a: BIG_384, k: cint) {.
       importc: "BIG_384_58_shr", cdecl.}
  proc BIG_384_shl*(a: BIG_384, s: cint) {.
       importc: "BIG_384_58_shl", cdecl.}
  proc BIG_384_fshr*(a: BIG_384, s: cint): cint {.
       importc: "BIG_384_58_fshr", cdecl.}
  proc BIG_384_fshl*(a: BIG_384, s: cint): cint {.
       importc: "BIG_384_58_fshl", cdecl.}
  proc BIG_384_dshl*(x: DBIG_384, s: cint) {.
       importc: "BIG_384_58_dshl", cdecl.}
  proc BIG_384_dmod*(x: BIG_384, y: DBIG_384, n: BIG_384) {.
       importc: "BIG_384_58_dmod", cdecl.}
  proc BIG_384_copy*(a: BIG_384, b: BIG_384) {.
       importc: "BIG_384_58_copy", cdecl.}
  proc BIG_384_norm*(a: BIG_384): Chunk {.
       importc: "BIG_384_58_norm", cdecl.}
  proc BIG_384_parity*(a: BIG_384): cint {.
       importc: "BIG_384_58_parity", cdecl.}
  proc BIG_384_jacobi*(a, p: BIG_384): cint {.
       importc: "BIG_384_58_jacobi", cdecl.}
  proc BIG_384_rcopy*(b, a: BIG_384) {.
       importc: "BIG_384_58_rcopy", cdecl.}
  proc BIG_384_mod*(x, n: BIG_384) {.
       importc: "BIG_384_58_mod", cdecl.}
  proc BIG_384_iszilch*(x: BIG_384): cint {.
       importc: "BIG_384_58_iszilch", cdecl.}

proc PAIR_BLS12381_ate*(res: ptr FP12_BLS12381, p: ptr ECP2_BLS12381,
                      q: ptr ECP_BLS12381) {.milagro_func.}
proc PAIR_BLS12381_double_ate*(res: ptr FP12_BLS12381, p: ptr ECP2_BLS12381,
                             q: ptr ECP_BLS12381, r: ptr ECP2_BLS12381,
                             s: ptr ECP_BLS12381) {.milagro_func.}
proc PAIR_BLS12381_fexp*(x: ptr FP12_BLS12381) {.milagro_func.}
proc PAIR_BLS12381_G1mul*(q: ptr ECP_BLS12381, b: BIG_384) {.milagro_func.}
proc PAIR_BLS12381_G2mul*(p: ptr ECP2_BLS12381, b: BIG_384) {.milagro_func.}
proc PAIR_BLS12381_GTpow*(x: ptr FP12_BLS12381, b: BIG_384) {.milagro_func.}
proc PAIR_BLS12381_GTmember*(x: ptr FP12_BLS12381): cint {.milagro_func.}
proc PAIR_BLS12381_another*(r: ptr FP12_BLS12381, pv: ptr ECP2_BLS12381,
                          qv: ptr ECP_BLS12381) {.milagro_func.}
proc PAIR_BLS12381_initmp*(r: ptr FP12_BLS12381) {.milagro_func.}
proc PAIR_BLS12381_miller*(res: ptr FP12_BLS12381; r: ptr FP12_BLS12381) {.
     milagro_func.}

proc ECP_BLS12381_generator*(g: ptr ECP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_mul*(p: ptr ECP_BLS12381, b: BIG_384) {.milagro_func.}
proc ECP_BLS12381_get*(x: BIG_384, y: BIG_384, p: ptr ECP_BLS12381): cint {.
     milagro_func.}

proc ECP_BLS12381_isinf*(p: ptr ECP_BLS12381): cint {.milagro_func.}
proc ECP_BLS12381_inf*(p: ptr ECP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_add*(p: ptr ECP_BLS12381, q: ptr ECP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_affine*(p: ptr ECP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_equals*(p: ptr ECP_BLS12381, q: ptr ECP_BLS12381): cint {.
     milagro_func.}
proc ECP_BLS12381_rhs*(r, x: ptr FP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_setx*(p: ptr ECP_BLS12381, x: BIG_384, s: cint): cint {.
     milagro_func.}
proc ECP_BLS12381_neg*(p: ptr ECP_BLS12381) {.milagro_func.}
proc ECP_BLS12381_map2point*(p: ptr ECP_BLS12381, h: ptr FP_BLS12381) {.
     milagro_func.}
proc ECP_BLS12381_set*(p: ptr ECP_BLS12381, x, y: BIG_384): cint {.milagro_func.}
proc ECP_BLS12381_cfp*(p: ptr ECP_BLS12381) {.milagro_func.}

proc ECP2_BLS12381_isinf*(p: ptr ECP2_BLS12381): cint {.milagro_func.}
proc ECP2_BLS12381_inf*(p: ptr ECP2_BLS12381) {.milagro_func.}
proc ECP2_BLS12381_neg*(p: ptr ECP2_BLS12381) {.milagro_func.}
proc ECP2_BLS12381_mul*(p: ptr ECP2_BLS12381, e: BIG_384) {.milagro_func.}
proc ECP2_BLS12381_add*(p: ptr ECP2_BLS12381, q: ptr ECP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_sub*(p: ptr ECP2_BLS12381, q: ptr ECP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_dbl*(p: ptr ECP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_frob*(p: ptr ECP2_BLS12381, frobConst: ptr FP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_generator*(g: ptr ECP2_BLS12381) {.milagro_func.}
proc ECP2_BLS12381_get*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381,
                      p: ptr ECP2_BLS12381): cint {.milagro_func.}
proc ECP2_BLS12381_affine*(p: ptr ECP2_BLS12381) {.milagro_func.}
proc ECP2_BLS12381_equals*(p: ptr ECP2_BLS12381, q: ptr ECP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_setx*(p: ptr ECP2_BLS12381, x: ptr FP2_BLS12381): cint {.
     milagro_func.}
proc ECP2_BLS12381_set*(p: ptr ECP2_BLS12381, x: ptr FP2_BLS12381,
                      y: ptr FP2_BLS12381): cint {.milagro_func.}
proc ECP2_BLS12381_rhs*(r: ptr FP2_BLS12381, x: ptr FP2_BLS12381) {.
     milagro_func.}
proc ECP2_BLS12381_map2point*(p: ptr ECP2_BLS12381, h: ptr FP2_BLS12381) {.
     milagro_func.}
proc ECP2_BLS12381_cfp*(p: ptr ECP2_BLS12381) {.milagro_func.}

proc FP_BLS12381_iszilch*(x: ptr FP_BLS12381): cint {.milagro_func.}
proc FP_BLS12381_redc*(x: BIG_384, y: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_nres*(y: ptr FP_BLS12381, x: BIG_384) {.milagro_func.}
proc FP_BLS12381_sqr*(w: ptr FP_BLS12381, x: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_qr*(x, sqrt_hint: ptr FP_BLS12381): cint {.milagro_func.}
proc FP_BLS12381_sqrt*(r, a, sqrt_hint: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_reduce*(x: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_one*(x: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_norm*(x: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_neg*(r: ptr FP_BLS12381, a: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_equals*(x: ptr FP_BLS12381, y: ptr FP_BLS12381): cint {.
     milagro_func.}
proc FP_BLS12381_mul*(x, y, z: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_add*(x, y, z: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_inv*(x, y, z: ptr FP_BLS12381) {.milagro_func.}
proc FP_BLS12381_cmove*(x, y: ptr FP_BLS12381, s: cint) {.milagro_func.}

proc FP2_BLS12381_inv*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_iszilch*(x: ptr FP2_BLS12381): cint {.milagro_func.}
proc FP2_BLS12381_cmove*(x, y: ptr FP2_BLS12381, s: cint) {.milagro_func.}
proc FP2_BLS12381_norm*(x: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_neg*(r: ptr FP2_BLS12381, a: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_from_BIGs*(w: ptr FP2_BLS12381, x, y: BIG_384) {.milagro_func.}
proc FP2_BLS12381_from_FPs*(w: ptr FP2_BLS12381, x, y: FP_BLS12381) {.milagro_func.}
proc FP2_BLS12381_copy*(w: ptr FP2_BLS12381, x: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_reduce*(w: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_one*(w: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_add*(w: ptr FP2_BLS12381, x: ptr FP2_BLS12381, y: ptr FP2_BLS12381) {.
     milagro_func.}
proc FP2_BLS12381_sub*(w: ptr FP2_BLS12381, x: ptr FP2_BLS12381, y: ptr FP2_BLS12381) {.
     milagro_func.}
proc FP2_BLS12381_mul*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381, z: ptr FP2_BLS12381) {.
     milagro_func.}
proc FP2_BLS12381_div2*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381){.milagro_func.}
proc FP2_BLS12381_sqr*(w: ptr FP2_BLS12381, x: ptr FP2_BLS12381){.milagro_func.}
proc FP2_BLS12381_qr*(x: ptr FP2_BLS12381): cint {.milagro_func.}
proc FP2_BLS12381_sqrt*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381) {.milagro_func.}
proc FP2_BLS12381_pow*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381, b: BIG_384){.milagro_func.}
proc FP2_BLS12381_equals*(x: ptr FP2_BLS12381, y: ptr FP2_BLS12381): cint {.
     milagro_func.}
proc FP12_BLS12381_equals*(x: ptr FP12_BLS12381, y: ptr FP12_BLS12381): cint {.
     milagro_func.}
proc FP12_BLS12381_isunity*(x: ptr FP12_BLS12381): cint {.milagro_func.}
proc FP12_BLS12381_mul*(x: ptr FP12_BLS12381, y: ptr FP12_BLS12381) {.milagro_func.}

# Debug
proc FP2_BLS12381_output*(x: ptr FP2_BLS12381) {.sideEffect, milagro_func.}
