# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Platform helpers
  ./platforms/platforms,
  # Standard library
  std/[monotimes, times, strformat, strutils, macros]

from ../blscurve import BLS_BACKEND

# warmup
proc warmup*() =
  # Warmup - make sure cpu is on max perf
  let start = cpuTime()
  var foo = 123
  for i in 0 ..< 300_000_000:
    foo += i*i mod 456
    foo = foo mod 789

  # Compiler shouldn't optimize away the results as cpuTime rely on sideeffects
  let stop = cpuTime()
  echo &"Warmup: {stop - start:>4.4f} s, result {foo} (displayed to avoid compiler optimizing warmup away)\n"

warmup()

when defined(gcc):
  echo "\nCompiled with GCC"
elif defined(clang):
  echo "\nCompiled with Clang"
elif defined(vcc):
  echo "\nCompiled with MSVC"
elif defined(icc):
  echo "\nCompiled with ICC"
else:
  echo "\nCompiled with an unknown compiler"

echo "Optimization level => no optimization: ", not defined(release), " | release: ", defined(release), " | danger: ", defined(danger)

when SupportsCPUName:
  echo "Running on ", cpuName(), "\n"

when SupportsGetTicks:
  echo "\n⚠️ Cycles measurements are approximate and use the CPU nominal clock: Turbo-Boost and overclocking will skew them."
  echo "i.e. a 20% overclock will be about 20% off (assuming no dynamic frequency scaling)"

echo "\nBackend: ", $BLS_BACKEND, ", mode: ", if defined(use32): $32 else: $(sizeof(int) * 8), "-bit"
echo "=".repeat(132) & '\n'

proc separator*() =
  echo "-".repeat(132)

proc report(op: string, start, stop: MonoTime, startClk, stopClk: int64, iters: int) =
  let ns = inNanoseconds((stop-start) div iters)
  let throughput = 1e9 / float64(ns)
  when SupportsGetTicks:
    echo &"{op:<67}     {throughput:>15.3f} ops/s    {ns:>9} ns/op    {(stopClk - startClk) div iters:>9} cycles"
  else:
    echo &"{op:<67}     {throughput:>15.3f} ops/s    {ns:>9} ns/op"

template bench*(op: string, iters: int, body: untyped): untyped =
  let start = getMonotime()
  when SupportsGetTicks:
    let startClk = getTicks()
  for _ in 0 ..< iters:
    body
  when SupportsGetTicks:
    let stopClk = getTicks()
  let stop = getMonotime()

  when not SupportsGetTicks:
    let startClk = -1'i64
    let stopClk = -1'i64

  report(op, start, stop, startClk, stopClk, iters)
