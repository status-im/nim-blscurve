# This file exposes the internal assembly optimized SHA256 routines
# of BLST.

import std/[strutils, os]

const srcPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0] & "/../../vendor/blst/src"
const headerPath = srcPath & "/sha256.h"

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

type
  BLST_SHA256_CTX* {.
    importc: "SHA256_CTX", header: headerPath, bycopy.} = object
    h: array[8, cuint]
    N: culonglong
    buf: array[64, byte]
    off: csize_t

## This module exports blst sha256 as C symbols, meaning a single definition
## can be linked with LTO instead of a separate symbol for every TU - it also
## allows using the library from `nlvm`
{.compile: "blst_sha256.c".}

func blst_sha256_init(ctx: var BLST_SHA256_CTX)
      {.importc: "blst_sha256_init", header: headerPath, importcFunc.}
func blst_sha256_update[T: byte|char](
       ctx: var BLST_SHA256_CTX,
       input: openArray[T]
     ){.importc: "blst_sha256_update", header: headerPath, importcFunc.}
func blst_sha256_final(
       digest: var array[32, byte],
       ctx: var BLST_SHA256_CTX
     ){.importc: "blst_sha256_final", header: headerPath, importcFunc.}

func init*(ctx: var BLST_SHA256_CTX) =
  blst_sha256_init(ctx)

func update*[T: byte|char](
       ctx: var BLST_SHA256_CTX,
       input: openArray[T]
     ) =
  blst_sha256_update(ctx, input)

func finalize*(digest: var array[32, byte], ctx: var BLST_SHA256_CTX) =
  blst_sha256_final(digest, ctx)

func bls_sha256_digest*[T: byte|char](
       digest: var array[32, byte],
       input: openArray[T]) =
  var ctx{.noinit.}: BLST_SHA256_CTX
  ctx.blst_sha256_init()
  ctx.blst_sha256_update(input)
  digest.blst_sha256_final(ctx)

func bls_sha256_digest*[T, U: byte|char](
       digest: var array[32, byte],
       input: openArray[T],
       sepTag: openArray[U]
     ) =
  # Workaround linker issue when using init/update/update/finalize
  # in ContextMultiAggregateVerify.init()
  var ctx{.noinit.}: BLST_SHA256_CTX
  ctx.blst_sha256_init()
  ctx.blst_sha256_update(input)
  ctx.blst_sha256_update(sepTag)
  digest.blst_sha256_final(ctx)
