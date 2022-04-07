import
  # Stdlib
  std/[unittest, random, sequtils, times],
  # Status
  nimcrypto/[sha2, hash],
  # BLSCurve
  ../blscurve/bls_public_exports

static: doAssert BLS_BACKEND == BLST

const Iters = 128

let seed = uint32(getTime().toUnix() and (1'i64 shl 32 - 1)) # unixTime mod 2^32
var rng = initRand(int64 seed)
echo "\n------------------------------------------------------\n"
echo "test_bls_sha256 xoshiro128+ (std/random) seed: ", seed

proc test() =
  let inputLen = rng.rand(128)
  let input = newSeqWith(inputLen, byte rng.rand(255))

  let a = sha256.digest(input)

  var b{.noinit.}: array[32, byte]
  b.bls_sha256_digest(input)
  doAssert a.data == b

suite "BLST internal SHA256 vs nimcrypto":
  test "BLST internal SHA256 vs nimcrypto":
    for _ in 0 ..< Iters:
      test()
