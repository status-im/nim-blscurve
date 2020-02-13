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
  # test "", "blscurve/hash_to_curve.nim"

  # Internal+Public BLS API - pre Ethereum2.0 v0.10
  # Those directly import the old API and internals
  # and do not need the "-d:BLS_USE_IETF_API=false" flag
  test "", "tests/old_spec/test_scheme.nim"
  test "", "tests/old_spec/test_vectors.nim"

  # Internal BLS API - IETF standard / post Ethereum2.0 v0.10
  # test "", "tests/hash_to_curve.nim"

  # Public BLS API - IETF standard / post Ethereum2.0 v0.10
  test "-d:BLS_USE_IETF_API=true", "tests/eth2_vectors.nim"
