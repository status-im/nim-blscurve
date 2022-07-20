mode = ScriptMode.Verbose

packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

installDirs = @["blscurve", "vendor"]
installFiles = @["blscurve.nim"]

### Dependencies
requires "nim >= 1.2.0",
         "nimcrypto",
         "stew",
         "https://github.com/status-im/nim-taskpools.git"

### Helper functions
proc test(args, path: string) =
  # Compilation language is controlled by TEST_LANG
  if not dirExists "build":
    mkDir "build"
  exec "nim " & getEnv("TEST_LANG", "c") & " " & getEnv("NIMFLAGS") & " " & args &
    " --outdir:build -r -f --skipParentCfg" &
    " --styleCheck:usages --styleCheck:hint" &
    " --hint[XDeclaredButNotUsed]:off --hint[Processing]:off " &
    path

### tasks
task test, "Run all tests":
  # Debug - test intermediate computations
  # test "", "blscurve/miracl/hkdf.nim"
  # test "", "blscurve/miracl/draft_v5/hash_to_curve_draft_v5.nim"
  # test "", "blscurve/miracl/hash_to_curve.nim"

  # Internal BLS API - IETF standard
  # test "", "tests/hash_to_curve_v7.nim"

  # Serialization
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/serialization.nim"
  # Public BLS API - IETF standard / Ethereum2.0 v1.0.0
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/eth2_vectors.nim"
  # key Derivation - EIP 2333
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/eip2333_key_derivation.nim"
  # Secret key to pubkey
  test "-d:BLS_FORCE_BACKEND=miracl", "tests/priv_to_pub.nim"

  test "-d:BLS_FORCE_BACKEND=blst", "tests/serialization.nim"
  # test "-d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  test "-d:BLS_FORCE_BACKEND=blst", "tests/eip2333_key_derivation.nim"
  test "-d:BLS_FORCE_BACKEND=blst", "tests/priv_to_pub.nim"

  # Internal SHA256
  test "-d:BLS_FORCE_BACKEND=blst", "tests/blst_sha256.nim"

  # Key spliting and recovery
  test "-d:BLS_FORCE_BACKEND=blst", "tests/secret_sharing.nim"

  when (defined(windows) and sizeof(pointer) == 4):
    # Eth2 vectors without batch verify
    test "-d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  else:
    test "--threads:on -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"

  # Windows 32-bit MinGW doesn't support SynchronizationBarrier for nim-taskpools.
  when not (defined(windows) and sizeof(pointer) == 4):
    # batch verification
    test "--threads:on -d:BLS_FORCE_BACKEND=blst", "tests/t_batch_verifier.nim"

    # Ensure benchmarks stay relevant.
    # TODO, solve "inconsistent operand constraints"
    # on 32-bit for asm volatile, this might be due to
    # incorrect RDTSC call in benchmark
    when defined(arm64) or defined(amd64):
      when not defined(macosx):
        exec "nim c --threads:on -d:BLS_FORCE_BACKEND=miracl -d:danger --outdir:build -r" &
              " --verbosity:0 --hints:off --warnings:off" &
              " benchmarks/bench_all.nim"

        exec "nim c --threads:on -d:BLS_FORCE_BACKEND=blst -d:danger --outdir:build -r" &
              " --verbosity:0 --hints:off --warnings:off" &
              " benchmarks/bench_all.nim"
      else:
        exec "nim c --threads:on -d:BLS_FORCE_BACKEND=miracl -d:danger --outdir:build -r" &
              " --verbosity:0 --hints:off --warnings:off" &
              " benchmarks/bench_all.nim"

        exec "nim c --threads:on -d:BLS_FORCE_BACKEND=blst -d:danger --outdir:build -r" &
              " --verbosity:0 --hints:off --warnings:off" &
              " benchmarks/bench_all.nim"

task bench, "Run benchmarks":
  if not dirExists "build":
    mkDir "build"

  exec "nim c --threads:on -d:danger --outdir:build -r" &
         " --verbosity:0 --hints:off --warnings:off" &
         " benchmarks/bench_all.nim"
