packageName   = "blscurve"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "BLS381-12 Curve implementation"
license       = "Apache License 2.0"

### Dependencies
requires "nim >= 0.19.6",
         "nimcrypto",
         "stew"

### Helper functions
proc test(path: string, lang = "c") =
  if not dirExists "build":
    mkDir "build"
  exec "nim " & lang & " --outdir:build -r " & path

### tasks
task test, "Run all tests":
  test "tests/all_tests.nim"
