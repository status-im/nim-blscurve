packageName   = "milagro_crypto"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = ""
license       = "Apache License 2.0"
srcDir        = "src"

### Dependencies
requires "nim >= 0.18.1"

### Helper functions
proc test(name: string, defaultLang = "c") =
  # TODO, don't forget to change defaultLang to `cpp` if the project requires C++
  if not dirExists "build":
    mkDir "build"
  if not dirExists "nimcache":
    mkDir "nimcache"
  --run
  --nimcache: "nimcache"
  switch("out", ("./build/" & name))
  setCommand defaultLang, "tests/" & name & ".nim"

### tasks
task test, "Run all tests":
  test "all_tests"
