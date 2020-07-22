#!/usr/bin/env -S nim e
mode = ScriptMode.Verbose

## ## This script is Nim's replacement for config[32/64].py files of Milagro
## library. It performs configuration of BLS381 curve for both 32bit and
## 64bit limbs. It also removes random/hash/crypto related functions.
##
## Usage:
##
## nim -e milagro.nims <srcpath> <dstpath>
##
## <srcpath> - source path of milagro's C sources. By default current working
## path will be used.
## <dstpath> - destination path where two directories `32` and `64` will be
## created and populated with generated BLS381 sources. By default current
## working path will be used.
import os, strutils

const coreh = """/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file core.h
 * @author Mike Scott
 * @brief Main Header File
 *
 */

#ifndef CORE_H
#define CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include "arch.h"

/* modulus types */

#define NOT_SPECIAL 0        /**< Modulus of no exploitable form */
#define PSEUDO_MERSENNE 1      /**< Pseudo-mersenne modulus of form $2^n-c$  */
#define MONTGOMERY_FRIENDLY 3  /**< Montgomery Friendly modulus of form $2^a(2^b-c)-1$  */
#define GENERALISED_MERSENNE 2 /**< Generalised-mersenne modulus of form $2^n-2^m-1$, GOLDILOCKS only */

/* Curve types */

#define WEIERSTRASS 0 /**< Short Weierstrass form curve  */
#define EDWARDS 1     /**< Edwards or Twisted Edwards curve  */
#define MONTGOMERY 2  /**< Montgomery form curve  */

/* Pairing-Friendly types */

#define NOT_PF 0
#define BN_CURVE 1
#define BLS12_CURVE 2
#define BLS24_CURVE 3
#define BLS48_CURVE 4

#define D_TYPE 0
#define M_TYPE 1

#define FP_ZILCH 0
#define FP_UNITY 1
#define FP_SPARSEST 2
#define FP_SPARSER 3
#define FP_SPARSE 4
#define FP_DENSE 5

#define NEGATOWER 0     // Extension field tower type
#define POSITOWER 1

/**
  @brief Portable representation of a big positive number
*/

typedef struct
{
    int len;   /**< length in bytes  */
    int max;   /**< max length allowed - enforce truncation  */
    char *val; /**< byte array  */
} octet;

#endif
"""

proc commentFunction(data, name: string): string =
  ## Procedure iterates over all lines in ``data`` and perform search for
  ## substring ``name`` and if it found starts with commenting all the lines
  ## until ``}`` will not be met.
  result = ""
  var state = 0
  for line in splitLines(data):
    if state == 0:
      if line.find(name) == -1:
        result.add(line & "\n")
        continue
      else:
        state = 1
    if state == 1:
      result.add("// " & line & "\n")
      if line.startsWith("}"):
        state = 2
      continue
    result.add(line & "\n")

proc inlineMul1(num: int, base: string): string =
  var r = ""
  r &= "\tt=(dchunk)a[0]*b[0]; c[0]=(chunk)t & BMASK_XXX; t=t>>BASEBITS_XXX;\n"

  for i in 1 ..< num:
    var k = 0
    r &= "\tt=t"
    while (k <= i):
      r &= "+(dchunk)a[$#]*b[$#]" % [$k, $(i - k)]
      k += 1
    r &= "; c[$#]=(chunk)t & BMASK_XXX; " % [$i]
    r &= "t=t>>BASEBITS_XXX;\n"

  for i in num ..< (2 * num - 1):
    var k = i - (num - 1)
    r &= "\tt=t"
    while (k <= num - 1):
      r &= "+(dchunk)a[$#]*b[$#]" % [$k, $(i - k)]
      k += 1
    r &= "; c[$#]=(chunk)t & BMASK_XXX; " % [$i]
    r &= "t=t>>BASEBITS_XXX;\n"

  r &= "\tc[$#]=(chunk)t;\n" % [$(2 * num - 1)]
  return r.replace("XXX", base)

proc inlineMul2(num: int, base: string): string =
  var r = ""
  for i in 0 ..< num:
    r &= "\td[$#]=(dchunk)a[$#]*b[$#];\n" % [$i, $i, $i]
  r &= "\n\ts=d[0];\n\tt = s; c[0]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX;\n"
  for k in 1 ..< num:
    r &= "\ts+=d[$#]; t=co+s " % [$k]
    for i in countdown(k, (k div 2) + 1):
      r &= "+(dchunk)(a[$#]-a[$#])*(b[$#]-b[$#])" % [$i, $(k - i), $(k - i), $i]
    r &= "; c[$#]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n" % [$k]
  r &= "\n"
  for k in num ..< (2 * num - 1):
    r &= "\ts-=d[$#]; t=co+s " % [$(k - num)]
    for i in countdown(num - 1, (k div 2) + 1):
      r &= "+(dchunk)(a[$#]-a[$#])*(b[$#]-b[$#])" % [$i, $(k - i), $(k - i), $i]
    r &= "; c[$#]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n" % [$k]
  r &= "\tc[$#]=(chunk)co;\n" % [$(2 * num - 1)]
  return r.replace("XXX", base)

proc inlineSqr(num: int, base: string): string =
  var r = ""
  r &= "\n\tt=(dchunk)a[0]*a[0]; c[0]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX;\n"
  for k in 1 ..< num:
    r &= "\tt= "
    for i in countdown(k, (k div 2) + 1):
      r &= "+(dchunk)a[$#]*a[$#]" % [$i, $(k - i)]
    r &= "; t+=t; t+=co;"
    if k mod 2 == 0 :
      r &= " t+=(dchunk)a[$#]*a[$#];" % [$(k div 2), $(k div 2)]
    r &= " c[$#]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n" % [$k]

  r &= "\n"

  for k in num ..< (num * 2 - 2):
    r &= "\tt= "
    for i in countdown(num-1, (k div 2) + 1):
      r &= "+(dchunk)a[$#]*a[$#]" % [$i, $(k - i)]
    r &= "; t+=t; t+=co;"
    if k mod 2 == 0 :
      r &= " t+=(dchunk)a[$#]*a[$#];" % [$(k div 2), $(k div 2)]
    r &= " c[$#]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n" % [$k]

  r &= "\tt=co; t+=(dchunk)a[$#]*a[$#]; c[$#]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n " %
    [$(num - 1), $(num - 1), $(2 * num - 2)]
  r &= "\tc[$#]=(chunk)co;\n" % [$(2 * num - 1)]
  return r.replace("XXX", base)

proc inlineRedc1(num: int, base: string): string =
  var r = ""

  r &= "\tt = d[0];\n"
  r &= "\tv[0] = ((chunk)t * MC)&BMASK_XXX;\n"
  r &= "\tt += (dchunk)v[0] * md[0];\n"
  r &= "\tt = (t >> BASEBITS_XXX) + d[1];\n"

  for i in 1 ..< num:
    var k = 1
    r &= "\tt += (dchunk)v[0] * md[$#] " % [$i]
    while k<i :
      r &= "+ (dchunk)v[$#]*md[$#]" % [$k, $(i - k)]
      k += 1
    r &= "; v[$#] = ((chunk)t * MC)&BMASK_XXX; " % [$i]
    r &= "t += (dchunk)v[$#] * md[0]; " % [$i]
    r &= "t = (t >> BASEBITS_XXX) + d[$#];\n" % [$(i + 1)]

  for i in num ..< (2 * num - 1):
    var k = i - (num - 1)
    r &= "\tt=t "
    while k <= num - 1:
      r &= "+ (dchunk)v[$#]*md[$#] " % [$k, $(i - k)]
      k += 1
    r &= "; a[$#] = (chunk)t & BMASK_XXX; " % [$(i - num)]
    r &= "t = (t >> BASEBITS_XXX) + d[$#];\n" % [$(i + 1)]

  r &= "\ta[$#] = (chunk)t & BMASK_XXX;\n" % [$(num - 1)]
  return r.replace("XXX", base)

proc inlineRedc2(num: int, base: string): string =
  var r = ""
  r &=  "\tt=d[0]; v[0]=((chunk)t*MC)&BMASK_XXX; t+=(dchunk)v[0]*md[0];  s=0; c=(t>>BASEBITS_XXX);\n\n"

  for k in 1 ..< num :
    r &= "\tt=d[$#]+c+s+(dchunk)v[0]*md[$#]" % [$k, $k]
    for i in countdown(k - 1, k div 2 + 1):
      r &= "+(dchunk)(v[$#]-v[$#])*(md[$#]-md[$#])" %
           [$(k - i), $i, $i, $(k - i)]
    r &= "; v[$#]=((chunk)t*MC)&BMASK_XXX; t+=(dchunk)v[$#]*md[0]; " % [$k, $k]
    r &= " dd[$#]=(dchunk)v[$#]*md[$#]; s+=dd[$#]; c=(t>>BASEBITS_XXX); \n" %
         [$k, $k, $k, $k]

  r &= "\n"
  for k in num ..< (2 * num - 1):
    r &= "\tt=d[$#]+c+s" % [$k]
    for i in countdown(num - 1, k div 2 + 1):
      r &= "+(dchunk)(v[$#]-v[$#])*(md[$#]-md[$#])" %
           [$(k - i), $i, $i, $(k - i)]
    r &= "; a[$#]=(chunk)t&BMASK_XXX;  s-=dd[$#]; c=(t>>BASEBITS_XXX); \n" %
         [$(k - num), $(k - num + 1)]

  r &= "\ta[$#]=d[$#]+((chunk)c&BMASK_XXX);\n" % [$(num - 1), $(2 * num - 1)]
  return r.replace("XXX", base)

proc commentLine(data, name: string): string =
  ## Procedure iterates over all lines in ``data`` and perform search for
  ## substring ``name``, if it found it will comment such line in ``C`` way.
  ## Returns modified ``data``.
  result = ""
  for line in splitLines(data):
    if line.find(name) == -1:
      result.add(line & "\n")
    else:
      result.add("// " & line & "\n")

proc checkFiles(src, tc: string): bool =
  ## Returns ``true`` if all the files in ``files`` array present in filesystem.
  let files = [
    "arch.h",
    "config_big.h",
    "config_field.h",
    "config_curve.h",
    "big.h", "big.c",
    "fp.h", "fp.c",
    "fp2.h", "fp2.c",
    "fp4.h", "fp4.c",
    "fp12.h", "fp12.c",
    "ecp.h", "ecp.c",
    "ecp2.h",  "ecp2.c",
    "pair.h", "pair.c",
    "rom_curve_" & tc & ".c",
    "rom_field_" & tc & ".c",
    "oct.c"
  ]
  result = true
  for item in files:
    if not system.fileExists(src / item):
      echo "ERROR: File [" & (src / item) & "] is missing!"
      result = false
      break

proc clearFiles(dst, tb, tf, tc, base: string) =
  ## Clear files in destination directory ``dst``.
  let bd = tb & "_" & base
  let files = [
    dst / ("core.h"),
    dst / ("arch.h"),
    dst / ("config_big_" & tb & "_" & base & ".h"),
    dst / ("config_field_" & tf & ".h"),
    dst / ("config_curve_" & tc & ".h"),
    dst / ("big_" & bd & ".c"),
    dst / ("big_" & bd & ".h"),
    dst / ("fp_" & tf & ".c"),
    dst / ("fp_" & tf & ".h"),
    dst / ("fp2_" & tf & ".c"),
    dst / ("fp2_" & tf & ".h"),
    dst / ("fp4_" & tf & ".c"),
    dst / ("fp4_" & tf & ".h"),
    dst / ("fp12_" & tf & ".c"),
    dst / ("fp12_" & tf & ".h"),
    dst / ("ecp_" & tc & ".c"),
    dst / ("ecp_" & tc & ".h"),
    dst / ("ecp2_" & tc & ".c"),
    dst / ("ecp2_" & tc & ".h"),
    dst / ("pair_" & tc & ".c"),
    dst / ("pair_" & tc & ".h"),
    dst / ("rom_curve_" & tc & ".c"),
    dst / ("rom_field_" & tc & ".c"),
    dst / ("oct.c")
  ]
  for item in files:
    if system.fileExists(item):
      rmFile(item)

# curveset("381","BLS12381","BLS12381","58","1",["-3","-1"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS12_CURVE","M_TYPE","NEGATIVEX","69","65","128")
# pfcurve_selected=True
# nbt = 381
# tf = BLS12381
# tc = BLS12381
# base = 58
# m8 = 1
# rz0, rz1 = [-3, -1]
# mt = "NOT_SPECIAL"
# qi = "0"
# ct = "WEIERSTRASS"
# ca = "0"
# pf = "BLS12_CURVE"
# stw = "M_TYPE"
# sx = "NEGATIVEX"
# g2 = "69"
# ab = "65"
# cs = "128"

proc logWriteFile(name: string, data: string) =
  echo "Writing data to file [", name, "]"
  writeFile(name, data)

proc curveSet(src, dst, nbt, tf, tc, base, m8, rz0, rz1, mt, qi, ct, ca, pf,
              stw, sx, g2, ab, cs: string) =
  let inbt = parseInt(nbt)
  let itb = int(inbt + (8 - (inbt mod 8)) mod 8)
  let inb = int(itb div 8)
  let tb = $itb
  let nb = $inb

  let bd = tb & "_" & base
  var fnameh, data: string
  var nmax: int

  # core.h
  fnameh = dst / "core.h"
  data = coreh.replace("@OS@", buildOS)
  logWriteFile(fnameh, data)

  # arch.h
  fnameh = dst / "arch.h"
  data = readFile(src / "arch.h")
  if base == "58":
    data = data.replace("@WL@", "64")
    nmax = 30
  else:
    data = data.replace("@WL@", "32")
    nmax = 14
  logWriteFile(fnameh, data)

  # config_big.h
  fnameh = dst / "config_big_" & bd & ".h"
  data = readFile(src / "config_big.h")
  data = data.replace("XXX", bd)
  data = data.replace("@NB@", nb)
  data = data.replace("@BASE@", base)
  logWriteFile(fnameh, data)

  # config_field.h
  fnameh = dst / "config_field_" & tf & ".h"
  data = readFile(src / "config_field.h")
  data = data.replace("XXX", bd)
  data = data.replace("YYY", tf)
  data = data.replace("@NBT@", nbt)
  data = data.replace("@M8@", m8)
  data = data.replace("@MT@", mt)

  data = data.replace("@RZ@", rz0)
  data = data.replace("@RZ2@", rz1)

  let intQi = parseInt(qi)
  let itw = intQi mod 10
  data = data.replace("@QI@", $itw)
  if (intQi div 10) > 0:
    data = data.replace("@TW@","POSITOWER")
  else:
    data = data.replace("@TW@","NEGATOWER")

  let ib = parseInt(base)
  var nlen = (1 + (( 8 * inb - 1) div ib))
  var sh = ib * nlen - inbt
  if sh > nmax:
    sh = nmax
  data = data.replace("@SH@", $sh)
  logWriteFile(fnameh, data)

  # config_curve.h
  fnameh = dst / "config_curve_" & tc & ".h"
  data = readFile(src / "config_curve.h")
  data = data.replace("XXX", bd)
  data = data.replace("YYY", tf)
  data = data.replace("ZZZ", tc)

  data = data.replace("@CT@", ct)
  data = data.replace("@CA@", ca)
  data = data.replace("@PF@", pf)

  data = data.replace("@ST@", stw)
  data = data.replace("@SX@", sx)
  data = data.replace("@CS@", cs)
  data = data.replace("@AB@", ab)
  data = data.replace("@G2@", g2)
  logWriteFile(fnameh, data)

  # big.c & big.h
  for item in ["big.c", "big.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "big_" & bd & ".h"
    else:
      fnameh = dst / "big_" & bd & ".c"
    data = readFile(src / item)
    data = data.replace("XXX", bd)
    if item.endsWith(".c"):
      if base == "58":
        data = data.commentFunction("BIG_384_58_random(")
        data = data.commentFunction("BIG_384_58_randomnum(")
        data = data.commentFunction("BIG_384_58_randtrunc(")
      else:
        data = data.commentFunction("BIG_384_29_random(")
        data = data.commentFunction("BIG_384_29_randomnum(")
        data = data.commentFunction("BIG_384_29_randtrunc(")
    else:
      if base == "58":
        data = data.commentLine("BIG_384_58_random(")
        data = data.commentLine("BIG_384_58_randomnum(")
        data = data.commentLine("BIG_384_58_randtrunc(")
      else:
        data = data.commentLine("BIG_384_29_random(")
        data = data.commentLine("BIG_384_29_randomnum(")
        data = data.commentLine("BIG_384_29_randtrunc(")

    data = data.replace("INLINE_MUL1", inlineMul1(nlen, bd))
    data = data.replace("INLINE_MUL2", inlineMul2(nlen, bd))
    data = data.replace("INLINE_SQR", inlineSqr(nlen, bd))
    data = data.replace("INLINE_REDC1", inlineRedc1(nlen, bd))
    data = data.replace("INLINE_REDC2", inlineRedc2(nlen, bd))

    logWriteFile(fnameh, data)

  # fp.c & fp.h
  for item in ["fp.c", "fp.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp_" & tf & ".h"
    else:
      fnameh = dst / "fp_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)

    if item.endsWith(".c"):
      data = data.commentFunction("FP_BLS12381_rand(")
    else:
      data = data.commentLine("FP_BLS12381_rand(")

    logWriteFile(fnameh, data)

  # ecp.c & ecp.h
  for item in ["ecp.c", "ecp.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "ecp_" & tc & ".h"
    else:
      fnameh = dst / "ecp_" & tc & ".c"
    data = readFile(src / item)
    data = data.replace("ZZZ", tc)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    logWriteFile(fnameh, data)

  # rom_curve_<>.c
  fnameh = dst / "rom_curve_" & tc & ".c"
  data = readFile(src / "rom_curve_" & tc & ".c")
  logWriteFile(fnameh, data)

  # rom_field_<>.c
  fnameh = dst / "rom_field_" & tc & ".c"
  data = readFile(src / "rom_field_" & tc & ".c")
  logWriteFile(fnameh, data)

  # fp2.h & fp2.c
  for item in ["fp2.c", "fp2.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp2_" & tf & ".h"
    else:
      fnameh = dst / "fp2_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)

    if item.endsWith(".c"):
      data = data.commentFunction("FP2_BLS12381_rand(")
    else:
      data = data.commentLine("FP2_BLS12381_rand(")

    logWriteFile(fnameh, data)

  # fp4.h & fp4.c
  for item in ["fp4.c", "fp4.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp4_" & tf & ".h"
    else:
      fnameh = dst / "fp4_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    data = data.replace("ZZZ", tc)

    if item.endsWith(".c"):
      data = data.commentFunction("FP4_BLS12381_rand(")
    else:
      data = data.commentLine("FP4_BLS12381_rand(")

    logWriteFile(fnameh, data)

  # fp12.h & fp12.c
  for item in ["fp12.c", "fp12.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp12_" & tf & ".h"
    else:
      fnameh = dst / "fp12_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    data = data.replace("ZZZ", tc)
    logWriteFile(fnameh, data)

  # ecp2.h & ecp2.c
  for item in ["ecp2.c", "ecp2.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "ecp2_" & tf & ".h"
    else:
      fnameh = dst / "ecp2_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("ZZZ", tc)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    logWriteFile(fnameh, data)

  # pair.h & pair.c
  for item in ["pair.c", "pair.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "pair_" & tc & ".h"
    else:
      fnameh = dst / "pair_" & tc & ".c"
    data = readFile(src / item)
    data = data.replace("ZZZ", tc)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    logWriteFile(fnameh, data)

  # oct.c
  data = readFile(src / "oct.c")
  data = data.commentFunction("OCT_rand")
  logWriteFile(dst / "oct.c", data)

const
  dstDirectory32 = "32"
  dstDirectory64 = "64"
  tb = "381"
  tf = "BLS12381"
  tc = "BLS12381"
  base32 = "29"
  base64 = "58"

var
  srcPath = "."
  dstPath = "."

if system.paramCount() == 4:
  srcPath = system.paramStr(3)
  dstPath = system.paramStr(4)
else:
  discard

## Check if source pattern files are present.
if not checkFiles(srcPath, tc):
  quit("FATAL: Could not find required files in [" & srcPath & "]!")

## Check if destination directory exists.
if not system.dirExists(dstPath):
  quit("FATAL: Destination path [" & dstPath & "] did not exists!")

let dstPath32 = dstPath / dstDirectory32
let dstPath64 = dstPath / dstDirectory64

## Check if directory for 32bit library is already present in filesystem
if not system.dirExists(dstPath32):
  mkDir(dstPath32)
else:
  clearFiles(dstPath32, tb, tf, tc, base32)

## Check if directory for 64bit library is already present in filesystem
if not system.dirExists(dstPath64):
  mkDir(dstPath64)
else:
  clearFiles(dstPath64, tb, tf, tc, base64)

## Generating 32bit version of library.
curveSet(srcPath, dstPath32, "381", "BLS12381", "BLS12381", "29", "1", "-3",
         "-1", "NOT_SPECIAL", "0", "WEIERSTRASS", "0", "BLS12_CURVE",
         "M_TYPE", "NEGATIVEX", "69", "65", "128")
## Generating 64bit version of library
curveSet(srcPath, dstPath64, "381", "BLS12381", "BLS12381", "58", "1", "-3",
         "-1", "NOT_SPECIAL", "0", "WEIERSTRASS", "0", "BLS12_CURVE",
         "M_TYPE", "NEGATIVEX", "69", "65", "128")

echo "SUCCESS: Milagro source files was successfully prepared!"
