/**
 * Copyright (c) 2024 Status Research & Development GmbH
 * Licensed under either of
 *  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 *  * MIT license ([LICENSE-MIT](LICENSE-MIT))
 * at your option.
 * This file may not be copied, modified, or distributed except according to
 * those terms.
 */

#ifndef BLST_NIM_H
#define BLST_NIM_H

// Nim does not support annotating pointer destinations with C `const`.
//
// This leads to errors on certain platforms and toolchains, e.g.:
//     expected 'const blst_p1_affine * const*'
//     but argument is of type 'blst_p1_affine **'
//     [-Wincompatible-pointer-types]
//
// To prevent these issues, offending function signatures are replaced
// with ones that lack C `const` annotations.


#define blst_p1s_to_affine blst_p1s_to_affine_replaced
#define blst_p1s_add blst_p1s_add_replaced
#define blst_p1s_mult_wbits_precompute blst_p1s_mult_wbits_precompute_replaced
#define blst_p1s_mult_wbits blst_p1s_mult_wbits_replaced
#define blst_p1s_mult_pippenger blst_p1s_mult_pippenger_replaced
#define blst_p1s_tile_pippenger blst_p1s_tile_pippenger_replaced

#define blst_p2s_to_affine blst_p2s_to_affine_replaced
#define blst_p2s_add blst_p2s_add_replaced
#define blst_p2s_mult_wbits_precompute blst_p2s_mult_wbits_precompute_replaced
#define blst_p2s_mult_wbits blst_p2s_mult_wbits_replaced
#define blst_p2s_mult_pippenger blst_p2s_mult_pippenger_replaced
#define blst_p2s_tile_pippenger blst_p2s_tile_pippenger_replaced

#define blst_miller_loop_n blst_miller_loop_n_replaced

#include "../../vendor/blst/bindings/blst.h"

#undef blst_p1s_to_affine
#undef blst_p1s_add
#undef blst_p1s_mult_wbits_precompute
#undef blst_p1s_mult_wbits
#undef blst_p1s_mult_pippenger
#undef blst_p1s_tile_pippenger

#undef blst_p2s_to_affine
#undef blst_p2s_add
#undef blst_p2s_mult_wbits_precompute
#undef blst_p2s_mult_wbits
#undef blst_p2s_mult_pippenger
#undef blst_p2s_tile_pippenger

#undef blst_miller_loop_n

void blst_p1s_to_affine(blst_p1_affine dst[], blst_p1 *points[],
                        size_t npoints);
void blst_p1s_add(blst_p1 *ret, blst_p1_affine *points[],
                                size_t npoints);
void blst_p1s_mult_wbits_precompute(blst_p1_affine table[], size_t wbits,
                                    blst_p1_affine *points[],
                                    size_t npoints);
void blst_p1s_mult_wbits(blst_p1 *ret, const blst_p1_affine table[],
                         size_t wbits, size_t npoints,
                         byte *scalars[], size_t nbits,
                         limb_t *scratch);
void blst_p1s_mult_pippenger(blst_p1 *ret, blst_p1_affine *points[],
                             size_t npoints, byte *scalars[],
                             size_t nbits, limb_t *scratch);
void blst_p1s_tile_pippenger(blst_p1 *ret, blst_p1_affine *points[],
                             size_t npoints, byte *scalars[],
                             size_t nbits, limb_t *scratch,
                             size_t bit0, size_t window);

void blst_p2s_to_affine(blst_p2_affine dst[], blst_p2 *points[],
                        size_t npoints);
void blst_p2s_add(blst_p2 *ret, blst_p2_affine *points[],
                                size_t npoints);
void blst_p2s_mult_wbits_precompute(blst_p2_affine table[], size_t wbits,
                                    blst_p2_affine *points[],
                                    size_t npoints);
void blst_p2s_mult_wbits(blst_p2 *ret, const blst_p2_affine table[],
                         size_t wbits, size_t npoints,
                         byte *scalars[], size_t nbits,
                         limb_t *scratch);
void blst_p2s_mult_pippenger(blst_p2 *ret, blst_p2_affine *points[],
                             size_t npoints, byte *scalars[],
                             size_t nbits, limb_t *scratch);
void blst_p2s_tile_pippenger(blst_p2 *ret, blst_p2_affine *points[],
                             size_t npoints, byte *scalars[],
                             size_t nbits, limb_t *scratch,
                             size_t bit0, size_t window);

void blst_miller_loop_n(blst_fp12 *ret, blst_p2_affine *Qs[],
                                        blst_p1_affine *Ps[],
                                        size_t n);

#endif
