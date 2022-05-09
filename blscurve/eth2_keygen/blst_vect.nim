## BEWARE!
##
## This module exists as a work-around for the following issue in the BLST library:
## https://github.com/supranational/blst/issues/29
##
## Since it's not possible to import vect.h and blst.h in the same compilation unit,
## we have to be careful to avoid producing imports to vect.h anywhere outside of
## this module.
##
## In other words, this module essentially wraps all functions that we want to use
## from the vect.h header in Nim functions that the Nim compiler knows how to link
## accross module boundaries, thus eliminating the need for any other compilation
## unit to depend on the vect.h header.

import
  os

type
  limb_t = uint64
  vec256 = array[4, limb_t]
  vec512 = array[8, limb_t]

const srcPath = currentSourcePath.parentDir & "/../../vendor/blst/src"

# XXX This was copied from hkdf_mod_r_blst.nim ithout much analysis
#     whether it's actually needed.
# Nim-Beacon-Chain compiles with --march=native by default
{.emit:"""
#if defined(__ADX__) && !defined(__BLST_PORTABLE__) /* e.g. -march=broadwell */
# define mul_mont_sparse_256 mulx_mont_sparse_256
# define redc_mont_256 redcx_mont_256
#endif
""".}

func redc_mont_256(ret: var vec256,
                   a: vec512,
                   p: vec256,
                   n0: limb_t)
  {.importc, header: srcPath & "/vect.h".}
  # Can use the redcx version with adx support

func redc_mont_256_nim*(ret: var vec256,
                        a: vec512,
                        p: vec256,
                        n0: limb_t) =
  redc_mont_256(ret, a, p, n0)

func mul_mont_sparse_256(ret: var vec256,
                         a, b, p: vec256,
                         n0: limb_t)
  {.importc, header: srcPath & "/vect.h".}
  # Can use the mulx version with adx support

func mul_mont_sparse_256_nim*(ret: var vec256,
                              a, b, p: vec256,
                              n0: limb_t) =
  mul_mont_sparse_256(ret, a, b, p, n0)
