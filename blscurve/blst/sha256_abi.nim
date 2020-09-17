# This file exposes the internal assembly optimized SHA256 routines
# of BLST.

import std/[strutils, os]

const srcPath = currentSourcePath.rsplit(DirSep, 1)[0]/".."/".."/"vendor"/"blst"/"src"
const headerPath = srcPath/"sha256.h"

type
  BLST_SHA256_CTX* {.
    importc: "SHA256_CTX",
    header: headerPath,
    incompleteStruct, byref.} = object

proc vec_zero(ret: pointer, num: csize_t)
    {.importc, exportc, header: srcPath/"vect.h", nodecl.}

proc blst_sha256_init*(ctx: var BLST_SHA256_CTX)
     {.importc: "sha256_init", header: headerPath, cdecl.}

proc blst_sha256_update*[T: byte|char](
       ctx: var BLST_SHA256_CTX,
       input: openarray[T]
     ){.importc: "sha256_update", header: headerPath, cdecl.}

proc blst_sha256_final*(
       digest: var array[32, byte],
       ctx: var BLST_SHA256_CTX
     ){.importc: "sha256_final", header: headerPath, cdecl.}

proc bls_sha256_digest*[T: byte|char](
       digest: var array[32, byte],
       input: openarray[T]) =
  var ctx{.noInit.}: BLST_SHA256_CTX
  ctx.blst_sha256_init()
  ctx.blst_sha256_update(input)
  digest.blst_sha256_final(ctx)
