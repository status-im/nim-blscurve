import strutils
from os import DirSep

const milagroPath = currentSourcePath.rsplit(DirSep, 1)[0] & DirSep &
                      "milagro_crypto" & DirSep & "generated" & DirSep

{.pragma: millagro_type, importc.}
{.pragma: millagro_func, importc, cdecl.}

## Compile required dependencies
{.compile: milagroPath & "rand.c"}
{.compile: milagroPath & "randapi.c"}
{.compile: milagroPath & "hash.c"}
{.compile: milagroPath & "oct.c"}
{.compile: milagroPath & "big_384_29.c"}
{.compile: milagroPath & "ecp_BLS381.c"}
{.compile: milagroPath & "ecp2_BLS381.c"}
{.compile: milagroPath & "fp_BLS381.c"}
{.compile: milagroPath & "fp2_BLS381.c"}
{.compile: milagroPath & "fp4_BLS381.c"}
{.compile: milagroPath & "fp12_BLS381.c"}
{.compile: milagroPath & "pair_BLS381.c"}
{.compile: milagroPath & "rom_curve_BLS381.c"}
{.compile: milagroPath & "rom_field_BLS381.c"}

{.deadCodeElim: on.}

type
  Chunk* = int32
  DChunk* = int64
  Sign32* = int32

const
  MODBYTES_384_29* = 48 # config_big_384_29.h
  BASEBITS_384_29* = 29 # config_big_384_29.h
  BIGBITS_384_29* = 8 * MODBYTES_384_29
  NLEN_384_29* = (1 + ((8 * MODBYTES_384_29 - 1) div BASEBITS_384_29))
  DNLEN_384_29* = 2 * NLEN_384_29

type
  Octet* {.importc: "octet", header: milagroPath & "amcl.h"} = object
    len* {.importc: "len".}: cint # Length in bytes
    max* {.importc: "max".}: cint # Max length allowed - enforce truncation
    val* {.importc: "val".}: pointer # Byte array

  BIG_384_29* = array[NLEN_384_29, Chunk]
  DBIG_384_29* = array[DNLEN_384_29, Chunk]

  FP_BLS381* = object
    g*: BIG_384_29
    xes*: Sign32

  FP2_BLS381* = object
    a*: FP_BLS381
    b*: FP_BLS381

  FP4_BLS381* = object
    a*: FP2_BLS381
    b*: FP2_BLS381

  FP12_BLS381* = object
    a*: FP4_BLS381
    b*: FP4_BLS381
    c*: FP4_BLS381

  ECP_BLS381* = object
    x*: FP_BLS381
    y*: FP_BLS381
    z*: FP_BLS381

  ECP2_BLS381* = object
    x*: FP2_BLS381
    y*: FP2_BLS381
    z*: FP2_BLS381

  GroupG1* = ECP_BLS381
  GroupG2* = ECP2_BLS381

proc OCT_fromHex*(dst: ptr Octet, src: ptr char) {.millagro_func.}
proc OCT_toHex*(src: ptr Octet, dst: ptr char) {.millagro_func.}
proc BIG_384_29_toBytes*(b: ptr char, a: BIG_384_29) {.millagro_func.}
proc BIG_384_29_output*(a: BIG_384_29) {.millagro_func.}
proc BIG_384_29_comp*(a: BIG_384_29, b: BIG_384_29): cint {.millagro_func.}
proc BIG_384_29_nbits*(a: BIG_384_29): cint {.millagro_func.}
proc BIG_384_29_shr*(a: BIG_384_29, k: cint) {.millagro_func.}
proc BIG_384_29_shl*(a: BIG_384_29, s: cint) {.millagro_func.}
proc BIG_384_29_fshr*(a: BIG_384_29, s: cint) {.millagro_func.}
proc BIG_384_29_fshl*(a: BIG_384_29, s: cint): cint {.millagro_func.}
proc BIG_384_29_dshl*(x: DBIG_384_29, s: cint) {.millagro_func.}
proc BIG_384_29_dmod*(x: BIG_384_29, y: DBIG_384_29, n: BIG_384_29) {.
     millagro_func.}
proc BIG_384_29_copy*(a: BIG_384_29, b: BIG_384_29) {.millagro_func.}
proc BIG_384_29_norm*(a: BIG_384_29) {.millagro_func.}
proc BIG_384_29_parity*(a: BIG_384_29): cint {.millagro_func.}  

proc PAIR_BLS381_ate*(res: ptr FP12_BLS381, p: ptr ECP2_BLS381,
                      q: ptr ECP_BLS381) {.millagro_func.}
proc PAIR_BLS381_double_ate*(res: ptr FP12_BLS381, p: ptr ECP2_BLS381,
                             q: ptr ECP_BLS381, r: ptr ECP2_BLS381,
                             s: ptr ECP_BLS381) {.millagro_func.}
proc PAIR_BLS381_fexp*(x: ptr FP12_BLS381) {.millagro_func.}
proc PAIR_BLS381_G1mul*(q: ptr ECP_BLS381, b: BIG_384_29) {.millagro_func.}
proc PAIR_BLS381_G2mul*(p: ptr ECP2_BLS381, b: BIG_384_29) {.millagro_func.}
proc PAIR_BLS381_GTpow*(x: ptr FP12_BLS381, b: BIG_384_29) {.millagro_func.}
proc PAIR_BLS381_GTmember*(x: ptr FP12_BLS381): cint {.millagro_func.}

proc ECP_BLS381_generator*(g: ptr ECP_BLS381) {.millagro_func.}
proc ECP_BLS381_mul*(p: ptr ECP_BLS381, b: BIG_384_29) {.millagro_func.}
proc ECP_BLS381_get*(x: BIG_384_29, y: BIG_384_29, p: ptr ECP_BLS381): cint {.
     millagro_func.}

proc ECP_BLS381_fromOctet*(p: ptr ECP_BLS381, w: ptr Octet): cint {.
     millagro_func.}
proc ECP_BLS381_mapit*(p: ptr ECP_BLS381, w: ptr Octet) {.millagro_func.}
proc ECP_BLS381_isinf*(p: ptr ECP_BLS381): cint {.millagro_func.}
proc ECP_BLS381_inf*(p: ptr ECP_BLS381) {.millagro_func.}
proc ECP_BLS381_add*(p: ptr ECP_BLS381, q: ptr ECP_BLS381) {.millagro_func.}
proc ECP_BLS381_affine*(p: ptr ECP_BLS381) {.millagro_func.}

proc ECP2_BLS381_isinf*(p: ptr ECP2_BLS381): cint {.millagro_func.}
proc ECP2_BLS381_inf*(p: ptr ECP2_BLS381) {.millagro_func.}
proc ECP2_BLS381_mul*(p: ptr ECP2_BLS381, e: BIG_384_29) {.millagro_func.}
proc ECP2_BLS381_toOctet*(w: ptr Octet, q: ptr ECP2_BLS381) {.millagro_func.}
proc ECP2_BLS381_fromOctet*(q: ptr ECP2_BLS381, w: ptr Octet): cint {.
     millagro_func.}
proc ECP2_BLS381_add*(p: ptr ECP2_BLS381, q: ptr ECP2_BLS381): cint {.
     millagro_func.}
proc ECP2_BLS381_generator*(g: ptr ECP2_BLS381) {.millagro_func.}
proc ECP2_BLS381_get*(x: ptr FP2_BLS381, y: ptr FP2_BLS381,
                      p: ptr ECP2_BLS381): cint {.millagro_func.}
proc ECP2_BLS381_affine*(p: ptr ECP2_BLS381) {.millagro_func.}

proc FP_BLS381_redc*(x: BIG_384_29, y: ptr FP_BLS381) {.millagro_func.}

proc FP2_BLS381_reduce*(w: ptr FP2_BLS381) {.millagro_func.}

proc FP12_BLS381_equals*(x: ptr FP12_BLS381, y: ptr FP12_BLS381): cint {.
     millagro_func.}
proc FP12_BLS381_toOctet*(w: ptr Octet, g: ptr FP12_BLS381) {.millagro_func.}
proc FP12_BLS381_fromOctet*(g: ptr FP12_BLS381, w: ptr Octet): cint {.
     millagro_func.}
