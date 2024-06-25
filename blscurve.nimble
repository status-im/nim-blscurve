mode = ScriptMode.Verbose

packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

installDirs = @["blscurve", "vendor"]
installFiles = @["blscurve.nim"]

### Dependencies
requires "nim >= 1.6.0",
         "nimcrypto",
         "stew",
         "results",
         "taskpools >= 0.0.5"

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" &
  (if verbose: "" else: " --verbosity:0 --hints:off") &
  " --skipParentCfg --skipUserCfg --outdir:build --nimcache:build/nimcache -f"

proc build(args, path: string) =
  exec nimc & " " & lang & " " & cfg & " " & flags & " " & args & " " & path

proc run(args, path: string) =
  build args & " --mm:refc -r", path
  if (NimMajor, NimMinor) > (1, 6):
    build args & " --mm:orc -r", path

### tasks
task test, "Run all tests":
  # Internal BLS API - IETF standard
  # run "", "tests/hash_to_curve_v7.nim"

  # Serialization
  run "-d:BLS_FORCE_BACKEND=blst", "tests/serialization.nim"
  # Public BLS API - IETF standard / Ethereum2.0 v1.0.0
  run "-d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  # key Derivation - EIP 2333
  run "-d:BLS_FORCE_BACKEND=blst", "tests/eip2333_key_derivation.nim"
  # Secret key to pubkey
  run "-d:BLS_FORCE_BACKEND=blst", "tests/priv_to_pub.nim"

  # Internal SHA256
  run "-d:BLS_FORCE_BACKEND=blst", "tests/blst_sha256.nim"

  # Key spliting and recovery
  run "-d:BLS_FORCE_BACKEND=blst", "tests/secret_sharing.nim"

  when (defined(windows) and sizeof(pointer) == 4):
    # Eth2 vectors without batch verify
    run "--threads:off -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  else:
    run "--threads:on -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"

  # Windows 32-bit MinGW doesn't support SynchronizationBarrier for nim-taskpools.
  when not (defined(windows) and sizeof(pointer) == 4):
    # batch verification
    run "--threads:on -d:BLS_FORCE_BACKEND=blst", "tests/t_batch_verifier.nim"

    # Ensure benchmarks stay relevant.
    # TODO, solve "inconsistent operand constraints"
    # on 32-bit for asm volatile, this might be due to
    # incorrect RDTSC call in benchmark
    when defined(arm64) or defined(amd64):
      run "--threads:on -d:BLS_FORCE_BACKEND=blst -d:danger --warnings:off",
          "benchmarks/bench_all.nim"

task bench, "Run benchmarks":
  run "--threads:on -d:danger --warnings:off", "benchmarks/bench_all.nim"
