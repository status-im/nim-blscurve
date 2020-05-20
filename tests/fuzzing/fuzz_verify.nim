import
  testutils/fuzzing, stew/byteutils,
  ../../blscurve, fuzzing_assumptions

test:
  block:
    if payload.len < pubkeyLen + signatureLen:
      break

    let
      signatureStart = payload.len - signatureLen
      pubkeyStart = signatureStart - pubkeyLen

    var sig: Signature
    if not sig.fromBytes(payload[signatureStart ..< (signatureStart + signatureLen)]):
      break

    var pubKey: PublicKey
    if not pubKey.fromBytes(payload[pubkeyStart ..< (pubkeyStart + pubkeyLen)]):
      break

    discard pubKey.verify(payload[0 ..< pubkeyStart], sig)

