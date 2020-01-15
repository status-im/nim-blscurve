packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

### Dependencies
requires "nim >= 1.0.4",
         "nimcrypto",
         "stew"

### tasks
task test, "Run all tests":
  # Private prerequisites/primitives
  exec "nim c -r --hints:off --warnings:off --outdir:build blscurve/hkdf.nim"

  # Public BLS API
  exec "nim c -r --hints:off --warnings:off --outdir:build tests/all_tests.nim"
