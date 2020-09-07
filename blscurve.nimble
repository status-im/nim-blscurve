packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

### Dependencies
requires "nim >= 1.0.4",
         "nimcrypto",
         "stew"

### Helper functions
proc test(env, path: string) =
  # Compilation language is controlled by BLS_TEST_LANG
  var lang = "c"
  if existsEnv"BLS_TEST_LANG":
    lang = getEnv"BLS_TEST_LANG"

  if not dirExists "build":
    mkDir "build"
  exec "nim " & lang & " " & env &
    " --outdir:build -r --hints:off --warnings:off " & path
  exec "nim " & lang & " -d:release " & env &
    " --outdir:build -r --hints:off --warnings:off " & path

### tasks
task test, "Run all tests":
  # Debug - test intermediate computations
  # test "", "blscurve/miracl/hkdf.nim"
  # test "", "blscurve/miracl/draft_v5/hash_to_curve_draft_v5.nim"
  # test "", "blscurve/miracl/hash_to_curve.nim"

  # Internal BLS API - IETF standard
  # test "", "tests/hash_to_curve_v7.nim"

  # Public BLS API - IETF standard / Ethereum2.0 v0.12.x
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/eth2_vectors.nim"
  # key Derivation - EIP 2333
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/eip2333_key_derivation.nim"
  # Secret key to pubkey
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/priv_to_pub.nim"

  when sizeof(int) == 8 and (defined(arm64) or defined(amd64)):
    test "-d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
    test "-d:BLS_FORCE_BACKEND=blst", "tests/eip2333_key_derivation.nim"
    test "-d:BLS_FORCE_BACKEND=blst", "tests/priv_to_pub.nim"

  # # Ensure benchmarks stay relevant. Ignore Windows 32-bit at the moment
  # if not defined(windows) or not existsEnv"PLATFORM" or getEnv"PLATFORM" == "x64":
  #   exec "nim c -d:danger --outdir:build -r" &
  #         " --verbosity:0 --hints:off --warnings:off" &
  #         " benchmarks/bench_all.nim"

# TODO: update benchmarks

# task bench, "Run benchmarks":
#   if not dirExists "build":
#     mkDir "build"

#   exec "nim c -d:danger --outdir:build -r" &
#          " --verbosity:0 --hints:off --warnings:off" &
#          " benchmarks/bench_all.nim"
