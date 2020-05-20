import
  stew/byteutils,
  ../test_locator,
  fuzzing_assumptions

var skipped = 0

let corpusDir = getAppDir() / "corpus"

removeDir corpusDir

template getInputBytes(test: JsonNode, fieldName: string): seq[byte] =
  test["input"][fieldName].getStr.hexToSeqByte

var inputIdx = 0
template nextInput: string =
  inc inputIdx
  "input" & $inputIdx

let verifyCorpusDir = corpusDir / "verify"
createDir verifyCorpusDir

for dir, test in walkTests("verify", skipped):
  let t = parseTest(dir / test)
  let
    message = t.getInputBytes "message"
    pubKey = t.getInputBytes "pubkey"
    signature = t.getInputBytes "signature"

  doAssert pubKey.len == fuzzing_assumptions.pubkeyLen and
           signature.len == fuzzing_assumptions.signatureLen

  writeFile(verifyCorpusDir / nextInput(), message & pubkey & signature)

