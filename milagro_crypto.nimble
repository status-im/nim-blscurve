packageName   = "milagro_crypto"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "Wrapper for the Apache Milagro Crypto Library"
license       = "Apache License 2.0"

### Dependencies
requires "nim >= 0.18.1", "nimcrypto"

### Helper functions
proc test(name: string, defaultLang = "c") =
  if not dirExists "build":
    mkDir "build"
  --run
  --nimcache: "nimcache"
  switch("out", ("./build/" & name))
  setCommand defaultLang, "tests/" & name & ".nim"

### tasks
task test, "Run all tests":
  test "all_tests"
