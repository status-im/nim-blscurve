# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Abstractions over platforms
# -----------------------------------------------

when defined(i386) or defined(amd64):
  import x86
  export getTicks, cpuName

  const SupportsCPUName* = true
  const SupportsGetTicks* = true
else:
  const SupportsCPUName* = false
  const SupportsGetTicks* = false


# Prevent compiler optimizing benchmark away
# -----------------------------------------------
# This doesn't always work unfortunately ...

proc volatilize(x: ptr byte) {.codegenDecl: "$# $#(char const volatile *x)", inline.} =
  discard

template preventOptimAway*[T](x: var T) =
  volatilize(cast[ptr byte](unsafeAddr x))

template preventOptimAway*[T](x: T) =
  volatilize(cast[ptr byte](x))
