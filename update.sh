#!/usr/bin/env bash
set -eu -o pipefail
cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")"

(( ${HAS_NIMTEROP:-0} )) || nimble install -y nimterop@0.6.13

CANDIDATE=blscurve/blst/blst_abi_candidate.nim
OUT=blscurve/blst/blst_abi.nim
NEW="$OUT.new"

TOAST=("$HOME"/.nimble/pkgs2/nimterop-0.6.13*/nimterop/toast)
"${TOAST[0]}" -n -p --prefix=_ --typemap=bool=int32 '-G=@\bin\b=src' '-G=@\bout\b=dst' -o="$CANDIDATE" vendor/blst/bindings/blst.h

sed -i.bak \
  -e "s|$PWD/||g" \
  -e "s|$HOME|~|g" \
  -e "s|nimterop-0.6.13-[0-9a-f]*|nimterop-0.6.13|g" \
  "$CANDIDATE"
rm -f "$CANDIDATE.bak"  # Portable GNU/macOS `sed` needs backup

cat > "$NEW" <<'EOF'
# ------------------------------------------------------------------------------------------------
# Manual edits
import std/[strutils, os]

const headerPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/blst+nim.h"

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
EOF

sed -E \
  -e '/^[[:space:]]*##/d' \
  -e 's/ ##.*//' \
  -e ':join' \
  -e '/[,;.\/]$/!bdone' \
  -e 'N' \
  -e 's/\n//' \
  -e 'bjoin' \
  -e ':done' \
  -e 's/; +/; /g' \
  -e '/^\{\.pragma:/d' \
  -e '/^  byte\* /d' \
  -e 's/ \{\.[^}]*impblstHdr\.\}:/ {.blst.}:/' \
  -e 's/ \{\.[^}]*impblstHdr\.\}//' \
  -e 's/^  (blst_[A-Za-z0-9_]+)\* = blst_opaque$/  c\1* {.importc: "\1", blstheader.} = object/' \
  -e 's/^  (blst_[A-Za-z0-9_]+)\* = object$/  c\1* {.importc: "\1", blstheader.} = object\n&/' \
  -e 's/^  cblst_/\n&/' \
  -e 's/\): bool$/): CTbool/' \
  -e 's/hash_or_encode: bool;/hash_or_encode: HashOrEncode;/' \
  -e 's/(dst|ret): array\[/\1: var array[/g' \
  -e '/blst_precompute_lines/s/: array\[/: var array[/' \
  -e 's/UncheckedArray\[(blst_[A-Za-z0-9_]+)\]/ptr \1/g' \
  -e 's/(points|Qs|Ps|scalars): (blst_[A-Za-z0-9_]+|byte)/\1: ptr ptr \2/g' \
  -e '/blst_pairing_get_dst/s/ptr byte$/ptr UncheckedArray[byte]/' \
  -e '/^proc /s/blst_/cblst_/g' \
  -e 's/^proc cblst_/proc blst_/' \
  -e 's|array\[typeof\(([0-9]*)\).*, byte\]|array[\1 div 8, byte]|' \
  -e 's|array\[typeof\(([0-9]*)\).*, limb_t\]|array[\1 div 8 div sizeof(limb_t), limb_t]|' \
  -e '/^proc /s/: ptr byte; [A-Za-z0-9_]*len: uint/: openArray[T]/' \
  -e '/^proc /s/: ptr byte; [A-Za-z0-9_]*len: uint/: openArray[U]/' \
  -e '/^proc /s/: ptr byte; [A-Za-z0-9_]*len: uint/: openArray[V]/' \
  -e '/openArray\[T\]/s/\*\(/*[T: byte|char](/' \
  -e '/openArray\[U\]/s/\[T: byte[|]char\]/[T,U: byte|char]/' \
  -e '/openArray\[V\]/s/\[T,U: byte[|]char\]/[T,U,V: byte|char]/' \
  -e 's/\]\(/](\n    /' \
  -e '/openArray\[U\]/s/; ([A-Za-z0-9_]+: openArray\[T\])/;\n    \1/' \
  "$CANDIDATE" >> "$NEW"

insert_before() {  # $1: anchor regex, $2: file, stdin: text to insert
  ANCHOR="$1" awk '
    !done && $0 ~ ENVIRON["ANCHOR"] {
      print "" ; while ((getline l < "/dev/stdin") > 0) print l ; done = 1
    }
    { print }' "$2" > "$2.bak"
  mv "$2.bak" "$2"
}

insert_after() {  # as insert_before, but continues the anchored declaration
  ANCHOR="$1" awk '
    { print }
    !done && $0 ~ ENVIRON["ANCHOR"] {
      while ((getline l < "/dev/stdin") > 0) print l ; done = 1
    }' "$2" > "$2.bak"
  mv "$2.bak" "$2"
}

insert_after '^var$' "$NEW" <<'EOF'
  # Generators
EOF

insert_before '^proc ' "$NEW" <<'EOF'
{.push cdecl, importc, header: headerPath.}

EOF

insert_before '^type$' "$NEW" <<'EOF'
# Do not importc the types that are fully defined
# otherwise they are improperly copied, for example
# when using Result or Option
# https://github.com/nim-lang/Nim/issues/9940
EOF

insert_after '^  blst_fp2\* = object$' "$NEW" <<'EOF'
    ## 0 is "real" part, 1 is "imaginary"
EOF

insert_after '^  blst_p1\* = object$' "$NEW" <<'EOF'
    ## BLS12-381-specific point operations.
EOF

insert_before '^var$' "$NEW" <<'EOF'
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

EOF

insert_before '^proc blst_fr_add\*\(' "$NEW" <<'EOF'
# BLS12-381-specific Fr operations (Modulo curve order)
EOF

insert_before '^proc blst_fp_add\*\(' "$NEW" <<'EOF'
# BLS12-381-specific Fp operations (Modulo BLS12-381 prime)
EOF

insert_before '^proc blst_fp2_add\*\(' "$NEW" <<'EOF'
# BLS12-381-specific Fp2 operations.
EOF

insert_before '^proc blst_fp12_sqr\*\(' "$NEW" <<'EOF'
# BLS12-381-specific Fp12 operations.
EOF

insert_after '^proc blst_fp12_frobenius_map\*\(' "$NEW" <<'EOF'
  ##   caveat lector! |n| has to be non-zero and not more than 3!
EOF

insert_before '^proc blst_p1_add\*\(' "$NEW" <<'EOF'
# BLS12-381-specific G1 operations.
EOF

insert_before '^proc blst_p2_add\*\(' "$NEW" <<'EOF'
# BLS12-381-specific G2 operations.
EOF

insert_before '^proc blst_p1s_to_affine\*\(' "$NEW" <<'EOF'
# Multi-scalar multiplications and other multi-point operations.
EOF

insert_before '^proc blst_map_to_g1\*\(' "$NEW" <<'EOF'
# Hash-to-curve operations.
EOF

insert_before '^proc blst_p1_serialize\*\(' "$NEW" <<'EOF'
# Zcash-compatible serialization/deserialization.
EOF

insert_before '^proc blst_keygen\*\[' "$NEW" <<'EOF'
# Specification defines two variants, 'minimal-signature-size' and
#  'minimal-pubkey-size'. To unify appearance we choose to distinguish
#  them by suffix referring to the public key type, more specifically
#  _pk_in_g1 corresponds to 'minimal-pubkey-size' and _pk_in_g2 - to
#  'minimal-signature-size'. It might appear a bit counterintuitive
#  in sign call, but no matter how you twist it, something is bound to
#  turn a little odd.

# Secret-key operations.
EOF

insert_before '^proc blst_miller_loop\*\(' "$NEW" <<'EOF'
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

EOF

insert_before '^proc blst_aggregate_in_g1\*\(' "$NEW" <<'EOF'
# Customarily applications aggregate signatures separately.
#  In which case application would have to pass NULLs for |signature|
#  to blst_pairing_aggregate calls and pass aggregated signature
#  collected with these calls to blst_pairing_finalverify. Inputs are
#  Zcash-compatible "straight-from-wire" byte vectors, compressed or
#  not.
EOF

insert_before '^proc blst_core_verify_pk_in_g1\*\[' "$NEW" <<'EOF'
# "One-shot" CoreVerify entry points.
EOF

mv "$NEW" "$OUT"
rm -f "$CANDIDATE"
