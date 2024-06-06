# This file exposes the internal assembly optimized SHA256 routines
# of BLST.

import std/[strutils, os]

const srcPath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]
const headerPath = srcPath & "/blst_sha256.h"

{.pragma: importcFunc, cdecl, gcsafe, noSideEffect, raises: [].}

type
  BLST_SHA256_CTX* {.
    importc: "BLST_SHA256_CTX", header: headerPath, bycopy.} = object
    h: array[8, cuint]
    N: culonglong
    buf: array[64, byte]
    off: csize_t

static:
  # sanity check - should be guaranteed by Nim / C
  doAssert sizeof(int) == sizeof(csize_t)

## This module exports blst sha256 as C symbols, meaning a single definition
## can be linked with LTO instead of a separate symbol for every TU - it also
## allows using the library from `nlvm`
{.compile: "blst_sha256.c".}

func blst_sha256_init(ctx: var BLST_SHA256_CTX)
      {.importc: "blst_sha256_init", importcFunc.}
func blst_sha256_update(
       ctx: var BLST_SHA256_CTX,
       input: pointer, len: csize_t
     ){.importc: "blst_sha256_update", importcFunc.}
func blst_sha256_final(
       digest: var array[32, byte],
       ctx: var BLST_SHA256_CTX
     ){.importc: "blst_sha256_final", importcFunc.}

func init*(ctx: var BLST_SHA256_CTX) =
  blst_sha256_init(ctx)

func update*[T: byte|char](
       ctx: var BLST_SHA256_CTX,
       input: openArray[T]
     ) =
  if input.len > 0:
    blst_sha256_update(ctx, unsafeAddr input[0], input.len.csize_t)

func finalize*(digest: var array[32, byte], ctx: var BLST_SHA256_CTX) =
  blst_sha256_final(digest, ctx)

func bls_sha256_digest*[T: byte|char](
       digest: var array[32, byte],
       input: openArray[T]) =
  var ctx{.noinit.}: BLST_SHA256_CTX
  ctx.blst_sha256_init()
  if input.len > 0:
    ctx.blst_sha256_update(unsafeAddr input[0], input.len.csize_t)
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
  if input.len > 0:
    ctx.blst_sha256_update(unsafeAddr input[0], input.len.csize_t)
  if sepTag.len > 0:
    ctx.blst_sha256_update(unsafeAddr sepTag[0], sepTag.len.csize_t)
  digest.blst_sha256_final(ctx)
