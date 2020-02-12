# Nim-BLSCurve
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

## This module converts Ethereum2 YAML test vectors to raw text vectors.
##
## Module requires NimYAML to be installed ``nimble install yaml``.
## Usage is:
## testconvert <input yaml file> <output path>
##   <input yaml file> - path to YAML file with Ethereum2 test vectors
##                       (default "test_bls.yml")
##   <output path> - path to directory where raw test vectors will be saved
##                   (default current directory)
import os, yaml

const
  DefaultVectorYML = "test_bls.yml"
  DefaultOutputPath = ""

proc createFile(path: string, filename: string): File =
  ## Create TEXT file in ``path``/``file`` and return File object.
  var pathname = if len(path) == 0: filename else: path / filename
  result = open(filename, mode = fmWrite)

proc getYaml(filename: string): YamlNode =
  ## Load YAML file and parse it, return root node object.
  var file = open(filename)
  var data = file.readAll()
  close(file)
  var ydom = loadDom(data)
  result = ydom.root

proc norm(a: string): string =
  ## Strip `0x` from hexadecimal strings.
  if len(a) > 2:
    if a[0] == '0' and (a[1] == 'X' or a[1] == 'x'):
      result = a[2..^1]
  else:
    result = a

proc case01(root: YamlNode, path: string = "") =
  var header = """## case01_message_hash_G2_uncompressed
##
## Format:
## domain\n
## message\n
## xre\n
## xim\n
## yre\n
## yim\n
## zre\n
## zim\n
## <empty line>\n"""
  var file = createFile(path, "case01_message_hash_G2_uncompressed.dat")
  try:
    file.writeLine(header)
    var node = root["case01_message_hash_G2_uncompressed"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        file.writeLine(norm(item["input"]["domain"].content))
        file.writeLine(norm(item["input"]["message"].content))
        for eitem in item["output"].items():
          for aitem in eitem:
            file.writeLine(norm(aitem.content))
    else:
      file.writeLine("")
      file.writeLine(norm(node["input"]["domain"].content))
      file.writeLine(norm(node["input"]["message"].content))
      for item in node["output"].items():
        for aitem in item:
          file.writeLine(norm(aitem.content))
  finally:
    file.close()

proc case02(root: YamlNode, path: string = "") =
  var header = """## case02_message_hash_G2_compressed
##
## Format:
## domain\n
## message\n
## xre\n
## xim\n
## <empty line>\n"""
  var file = createFile(path, "case02_message_hash_G2_compressed.dat")
  try:
    file.writeLine(header)
    var node = root["case02_message_hash_G2_compressed"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        file.writeLine(norm(item["input"]["domain"].content))
        file.writeLine(norm(item["input"]["message"].content))
        for eitem in item["output"].items():
          file.writeLine(norm(eitem.content))
    else:
      file.writeLine("")
      file.writeLine(norm(node["input"]["domain"].content))
      file.writeLine(norm(node["input"]["message"].content))
      for item in node["output"].items():
        file.writeLine(norm(item.content))
  finally:
    file.close()

proc case03(root: YamlNode, path: string = "") =
  var header = """## case03_private_to_public_key
##
## Format:
## private key\n
## public key\n
## <empty line>\n"""
  var file = createFile(path, "case03_private_to_public_key.dat")
  try:
    file.writeLine(header)
    var node = root["case03_private_to_public_key"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        file.writeLine(norm(item["input"].content))
        file.writeLine(norm(item["output"].content))
    else:
      file.writeLine("")
      file.writeLine(norm(node["input"].content))
      file.writeLine(norm(node["output"].content))
  finally:
    file.close()

proc case04(root: YamlNode, path: string = "") =
  var header = """## case04_sign_messages
##
## Format:
## domain\n
## message\n
## private key\n
## signature\n
## <empty line>\n"""
  var file = createFile(path, "case04_sign_messages.dat")
  try:
    file.writeLine(header)
    var node = root["case04_sign_messages"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        file.writeLine(norm(item["input"]["domain"].content))
        file.writeLine(norm(item["input"]["message"].content))
        file.writeLine(norm(item["input"]["privkey"].content))
        file.writeLine(norm(item["output"].content))
    else:
      file.writeLine("")
      file.writeLine(norm(node["input"]["domain"].content))
      file.writeLine(norm(node["input"]["message"].content))
      file.writeLine(norm(node["input"]["privkey"].content))
      file.writeLine(norm(node["output"].content))
  finally:
    file.close()

proc case06(root: YamlNode, path: string = "") =
  var header = """## case06_aggregate_sigs
##
## Format:
## signature1\n
## signature2\n
## signature3\n
## aggregated signature\n
## <empty line>\n"""
  var file = createFile(path, "case06_aggregate_sigs.dat")
  try:
    file.writeLine(header)
    var node = root["case06_aggregate_sigs"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        for iitem in item["input"].items():
          file.writeLine(norm(iitem.content))
        file.writeLine(norm(item["output"].content))
    else:
      file.writeLine("")
      for item in node["input"].items():
        file.writeLine(norm(item.content))
      file.writeLine(norm(node["output"].content))
  finally:
    file.close()

proc case07(root: YamlNode, path: string = "") =
  var header = """## case07_aggregate_pubkeys
##
## Format:
## public-key1\n
## public-key2\n
## public-key3\n
## aggregated public-key\n
## <empty line>\n"""
  var file = createFile(path, "case07_aggregate_pubkeys.dat")
  try:
    file.writeLine(header)
    var node = root["case07_aggregate_pubkeys"]
    if node.kind == ySequence:
      for item in node.items():
        file.writeLine("")
        for iitem in item["input"].items():
          file.writeLine(norm(iitem.content))
        file.writeLine(norm(item["output"].content))
    else:
      file.writeLine("")
      for item in node["input"].items():
        file.writeLine(norm(item.content))
      file.writeLine(norm(node["output"].content))
  finally:
    file.close()

when isMainModule:
  var fileName, outputPath: string
  if paramCount() == 0:
    fileName = DefaultVectorYML
    outputPath = DefaultOutputPath
  elif paramCount() == 1:
    fileName = paramStr(1)
    outputPath = DefaultOutputPath
  elif paramCount() >= 2:
    fileName = paramStr(1)
    outputPath = paramStr(2)

  var root = getYaml(fileName)
  case01(root, outputPath)
  case02(root, outputPath)
  case03(root, outputPath)
  case04(root, outputPath)
  case06(root, outputPath)
  case07(root, outputPath)
