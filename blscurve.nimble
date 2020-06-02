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
proc test(env, path: string, lang = "c") =
  if not dirExists "build":
    mkDir "build"
  exec "nim " & lang & " " & env &
    " --outdir:build -r --hints:off --warnings:off " & path

### tasks
task test, "Run all tests":
  # Debug - test intermediate computations
  # test "", "blscurve/hkdf.nim"
  # test "", "blscurve/draft_v5/hash_to_curve_draft_v5.nim"
  # test "", "blscurve/hash_to_curve.nim"

  # Internal BLS API - IETF standard
  # test "", "tests/hash_to_curve_v5.nim"
  # test "", "tests/hash_to_curve_v7.nim"

  # Public BLS API - IETF standard / Ethereum2.0 v0.10.x ~ v0.11.x
  test "-d:BLS_ETH2_SPEC=\"v0.11.x\"", "tests/eth2_vectors.nim"
  # Public BLS API - IETF standard / Ethereum2.0 v0.12.x
  test "-d:BLS_ETH2_SPEC=\"v0.12.x\"", "tests/eth2_vectors.nim"

  # key Derivation - EIP 2333
  test "", "tests/eip2333_key_derivation.nim"

  # Ensure benchmarks stay relevant. Ignore Windows 32-bit at the moment
  if not defined(windows) or not existsEnv"PLATFORM" or getEnv"PLATFORM" == "x64":
    exec "nim c -d:danger --outdir:build -r" &
          " --verbosity:0 --hints:off --warnings:off" &
          " benchmarks/bench_all.nim"

task bench, "Run benchmarks":
  if not dirExists "build":
    mkDir "build"

  exec "nim c -d:danger --outdir:build -r" &
         " --verbosity:0 --hints:off --warnings:off" &
         " benchmarks/bench_all.nim"
