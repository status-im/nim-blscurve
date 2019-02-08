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
import ospaths, strutils

const amclh = """/*
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*/


#ifndef AMCL_H
#define AMCL_H

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

#define NOT 0
#define BN 1
#define BLS 2

#define D_TYPE 0
#define M_TYPE 1

#define FP_ZERO 0
#define FP_UNITY 1
#define FP_SPARSER 2
#define FP_SPARSE 3
#define FP_DENSE 4

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
    "ecp2.h", "ecp.c",
    "pair.h", "pair.c",
    "rom_curve_" & tc & ".c",
    "rom_field_" & tc & ".c",
    "oct.c"
  ]
  result = true
  for item in files:
    if not fileExists(src / item):
      echo "ERROR: File [" & (src / item) & "] is missing!"
      result = false
      break

proc clearFiles(dst, tb, tf, tc, base: string) =
  ## Clear files in destination directory ``dst``.
  let bd = tb & "_" & base
  let files = [
    dst / ("amcl.h"),
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
    if fileExists(item):
      rmFile(item)

proc curveSet(src, dst, tb, tf, tc, nb, base, nbt, m8, mt, ct, pf, stw, sx, ab,
              cs: string) =
  let bd = tb & "_" & base
  var fnameh, data: string
  var nmax: int

  # amcl.h
  fnameh = dst / "amcl.h"
  data = amclh.replace("@OS@", buildOS)
  writeFile(fnameh, data)

  # arch.h
  fnameh = dst / "arch.h"
  data = readFile(src / "arch.h")
  if base == "58":
    data = data.replace("@WL@", "64")
    nmax = 30
  else:
    data = data.replace("@WL@", "32")
    nmax = 14
  writeFile(fnameh, data)

  # config_big.h
  fnameh = dst / "config_big_" & bd & ".h"
  data = readFile(src / "config_big.h")
  data = data.replace("XXX", bd)
  data = data.replace("@NB@", nb)
  data = data.replace("@BASE@", base)
  writeFile(fnameh, data)

  # config_field.h
  fnameh = dst / "config_field_" & tf & ".h"
  data = readFile(src / "config_field.h")
  data = data.replace("XXX", bd)
  data = data.replace("YYY", tf)
  data = data.replace("@NBT@", nbt)
  data = data.replace("@M8@", m8)
  data = data.replace("@MT@", mt)
  var ib = parseInt(base)
  var inb = parseInt(nb)
  var inbt = parseInt(nbt)
  var sh = ib * (1 + ((8 * inb - 1) div ib)) - inbt
  if sh > nmax:
    sh = nmax
  data = data.replace("@SH@", $sh)
  writeFile(fnameh, data)

  # config_curve.h
  fnameh = dst / "config_curve_" & tc & ".h"
  data = readFile(src / "config_curve.h")
  data = data.replace("XXX", bd)
  data = data.replace("YYY", tf)
  data = data.replace("ZZZ", tc)
  data = data.replace("@CT@", ct)
  data = data.replace("@PF@", pf)
  data = data.replace("@ST@", stw)
  data = data.replace("@SX@", sx)
  data = data.replace("@CS@", cs)
  data = data.replace("@AB@", ab)
  writeFile(fnameh, data)

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
      else:
        data = data.commentFunction("BIG_384_29_random(")
        data = data.commentFunction("BIG_384_29_randomnum(")
    else:
      if base == "58":
        data = data.commentLine("BIG_384_58_random(")
        data = data.commentLine("BIG_384_58_randomnum(")
      else:
        data = data.commentLine("BIG_384_29_random(")
        data = data.commentLine("BIG_384_29_randomnum(")

    writeFile(fnameh, data)

  # fp.c & fp.h
  for item in ["fp.c", "fp.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp_" & tf & ".h"
    else:
      fnameh = dst / "fp_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    writeFile(fnameh, data)

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
    writeFile(fnameh, data)

  # rom_curve_<>.c
  fnameh = dst / "rom_curve_" & tc & ".c"
  data = readFile(src / "rom_curve_" & tc & ".c")
  writeFile(fnameh, data)

  # rom_field_<>.c
  fnameh = dst / "rom_field_" & tc & ".c"
  data = readFile(src / "rom_field_" & tc & ".c")
  writeFile(fnameh, data)

  # fp2.h & fp2.c
  for item in ["fp2.c", "fp2.h"]:
    if item.endsWith(".h"):
      fnameh = dst / "fp2_" & tf & ".h"
    else:
      fnameh = dst / "fp2_" & tf & ".c"
    data = readFile(src / item)
    data = data.replace("YYY", tf)
    data = data.replace("XXX", bd)
    writeFile(fnameh, data)

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
    writeFile(fnameh, data)

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
    writeFile(fnameh, data)

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
    writeFile(fnameh, data)

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
    writeFile(fnameh, data)

  # oct.c
  data = readFile(src / "oct.c")
  data = data.commentFunction("OCT_rand")
  writeFile(dst / "oct.c", data)

const
  dstDirectory32 = "32"
  dstDirectory64 = "64"
  tb = "384"
  tf = "BLS381"
  tc = "BLS381"
  base32 = "29"
  base64 = "58"

var
  srcPath = "."
  dstPath = "."

if paramStr(0).toLowerAscii() == "nim" and paramCount() == 4:
  srcPath = paramStr(3)
  dstPath = paramStr(4)
else:
  discard

## Check if source pattern files are present.
if not checkFiles(srcPath, tc):
  quit("FATAL: Could not find required files in [" & srcPath & "]!")

## Check if destination directory exists.
if not dirExists(dstPath):
  quit("FATAL: Destination path did not exists!")

let dstPath32 = dstPath / dstDirectory32
let dstPath64 = dstPath / dstDirectory64

## Check if directory for 32bit library is already present in filesystem
if not dirExists(dstPath32):
  mkDir(dstPath32)
else:
  clearFiles(dstPath32, tb, tf, tc, base32)

## Check if directory for 64bit library is already present in filesystem
if not dirExists(dstPath64):
  mkDir(dstPath64)
else:
  clearFiles(dstPath64, tb, tf, tc, base64)

## Generating 32bit version of library.
curveSet(srcPath, dstPath32, "384", "BLS381", "BLS381",
         "48", "29", "381", "3", "NOT_SPECIAL", "WEIERSTRASS", "BLS",
         "M_TYPE", "NEGATIVEX", "65", "128")
## Generating 64bit version of library
curveSet(srcPath, dstPath64, "384", "BLS381", "BLS381",
         "48", "58", "381", "3", "NOT_SPECIAL", "WEIERSTRASS", "BLS",
         "M_TYPE", "NEGATIVEX", "65", "128")
echo "SUCCESS: Milagro source files was successfully prepared!"
