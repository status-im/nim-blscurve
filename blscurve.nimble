mode = ScriptMode.Verbose

packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

installDirs = @["blscurve", "vendor"]
installFiles = @["blscurve.nim"]

### Dependencies
requires "nim >= 2.0.14",
         "nimcrypto >= 0.7.0",
         "results >= 0.5.0",
         "stew >= 0.5.0",
         "taskpools >= 0.2.2"

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]
let platform = getEnv("PLATFORM", "")

from std/os import quoteShell

let cfg =
  " --styleCheck:usages --styleCheck:error" &
  (if verbose: "" else: " --verbosity:0") &
  " --skipParentCfg --skipUserCfg --outdir:build -f " &
  quoteShell("--nimcache:build/nimcache/$projectName")

proc build(args, path: string) =
  exec nimc & " " & lang & " " & cfg & " " & flags & " " & args & " " & path

proc run(args, path: string) =
  build args & " -r", path

proc runTests(args: string) =
  # Internal BLS API - IETF standard
  # run args, "tests/hash_to_curve_v7.nim"

  # Serialization
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/serialization.nim"
  # Public BLS API - IETF standard / Ethereum2.0 v1.0.0
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  # key Derivation - EIP 2333
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/eip2333_key_derivation.nim"
  # Secret key to pubkey
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/priv_to_pub.nim"

  # Internal SHA256
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/blst_sha256.nim"

  # Key spliting and recovery
  run args & " -d:BLS_FORCE_BACKEND=blst", "tests/secret_sharing.nim"

  when (defined(windows) and sizeof(pointer) == 4):
    # Eth2 vectors without batch verify
    run args & " --threads:off -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"
  else:
    run args & " --threads:on -d:BLS_FORCE_BACKEND=blst", "tests/eth2_vectors.nim"

  # Windows 32-bit MinGW doesn't support SynchronizationBarrier for nim-taskpools.
  when not (defined(windows) and sizeof(pointer) == 4):
    # batch verification
    run args & " --threads:on -d:BLS_FORCE_BACKEND=blst", "tests/t_batch_verifier.nim"

### tasks
task test, "Run all tests":
  for args in ["--mm:refc", "--mm:orc"]:
    runTests args

    # Ensure benchmarks stay relevant.
    # TODO, solve "inconsistent operand constraints"
    # on 32-bit for asm volatile, this might be due to
    # incorrect RDTSC call in benchmark
    when defined(arm64) or defined(amd64):
      run args & " --threads:on -d:BLS_FORCE_BACKEND=blst -d:danger --warnings:off",
          "benchmarks/bench_all.nim"

      # Build but don't run MSM bench, it's slow
      build args & " -d:BLS_FORCE_BACKEND=blst -d:danger --warnings:off",
          "benchmarks/bls12381_msm_g1.nim"

task test_asan, "Run all tests with ASAN / TSAN":
  if platform != "x86":
    try:
      exec "echo '#if __clang_major__ < 20\n#error\n#endif' | clang -E - >/dev/null"
    except OSError:
      return

    # https://clang.llvm.org/docs/AddressSanitizer.html
    putEnv("ASAN_OPTIONS", "detect_leaks=0:detect_stack_use_after_return=1")
    # https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html
    putEnv("UBSAN_OPTIONS", "print_stacktrace=1")
    # https://clang.llvm.org/docs/ThreadSanitizer.html
    for sanitizer in ["address", "thread"]:
      if sanitizer == "thread" and defined(windows):
        continue
      var sanArgs =
        " --mm:orc -d:useMalloc --cc:clang --debugger:native" &
        " --passC:-fsanitize=" & sanitizer & ",undefined" &
        " --passL:-fsanitize=" & sanitizer & ",undefined" &
        " --passC:-fno-sanitize-recover=undefined" &
        " --passC:-fno-sanitize-merge" &
        " --passC:-fno-omit-frame-pointer"
      if sanitizer == "thread":
        sanArgs.add " -d:taskpoolsTsan"
      runTests sanArgs

task bench, "Run benchmarks":
  for args in ["--mm:refc", "--mm:orc"]:
    run args & " --threads:on -d:danger --warnings:off", "benchmarks/bench_all.nim"
