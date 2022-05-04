import
  # Stdlib
  std/[random, sequtils],
  # Status
  nimcrypto/[sha2, hash],
  # BLSCurve
  ../blscurve/bls_public_exports,
  # Bench
  ./bench_templates

static: doAssert BLS_BACKEND == BLST

var rng = initRand(int64 0xDECAF)

proc benchSHA256_nimcrypto[T](msg: openArray[T], msgComment: string, iters: int) =
  var digest: MDigest[256]
  bench("SHA256 - " & msgComment & " - nimcrypto", iters):
    digest = sha256.digest(msg)

proc benchSHA256_blst[T](msg: openArray[T], msgComment: string, iters: int) =
  var digest: array[32, byte]
  bench("SHA256 - " & msgComment & " - BLST", iters):
    digest.bls_sha256_digest(msg)

when isMainModule:
  proc main() =
    block:
      let msg32B = newSeqWith(32, byte rng.rand(255))
      benchSHA256_nimcrypto(msg32B, "32B", 32)
      benchSHA256_blst(msg32B, "32B", 32)
    block:
      let msg128B = newSeqWith(128, byte rng.rand(255))
      benchSHA256_nimcrypto(msg128B, "128B", 128)
      benchSHA256_blst(msg128B, "128B", 128)
    block:
      let msg5MB = newSeqWith(5_000_000, byte rng.rand(255))
      benchSHA256_nimcrypto(msg5MB, "5MB", 16)
      benchSHA256_blst(msg5MB, "5MB", 16)

  main()
