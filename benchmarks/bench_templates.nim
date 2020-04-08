# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Helpers
  ./helpers/timers,
  # Standard library
  std/[monotimes, times, strformat, strutils, macros]

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

echo "\n⚠️ Cycles measurements are approximate and use the CPU nominal clock: Turbo-Boost and overclocking will skew them."
echo "==========================================================================================================\n"
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

when (sizeof(int) == 4) or defined(use32):
  echo "⚠️ Warning: using Milagro with 32-bit limbs"
else:
  echo "Using Milagro with 64-bit limbs"

when defined(i386) or defined(amd64):
  import ./helpers/x86
  echo "Running on ", cpuName(), "\n\n"

proc report(op: string, start, stop: MonoTime, startClk, stopClk: int64, iters: int) =
  let ns = inNanoseconds((stop-start) div iters)
  let throughput = 1e9 / float64(ns)
  echo &"{op:<55}     {throughput:>20.3f} ops/s     {ns:>9} ns/op     {(stopClk - startClk) div iters:>9} cycles"

template bench*(op: string, iters: int, body: untyped): untyped =
  bind getMonotime, getTicks, report

  let start = getMonotime()
  let startClk = getTicks()
  for _ in 0 ..< iters:
    body
  let stopClk = getTicks()
  let stop = getMonotime()

  report(op, start, stop, startClk, stopClk, iters)
