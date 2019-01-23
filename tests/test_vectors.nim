import strutils
import nimcrypto/[sysrand, hash, keccak, utils]
import ../milagro_crypto/scheme3

when isMainModule:
  # var a1, a2: BIG_384
  # var f1, f2: FP_BLS381
  # var fp1, fp2: FP2_BLS381
  # echo a1.fromHex("57a861b8347295eb6e399dda61f3fe30dd1d650c06dc0fe3a02a1fa2d5aad54f")
  # echo a2.fromHex("330a4423e5dfcccd577025ea63bc70d565a07e3d952d61f696eb52aaae5a906e")
  # echo $a1
  # echo $a2
  # f1 = nres(a1)
  # f2 = nres(a2)
  # echo $f1
  # echo $f2

  # fp1.fromFPs(f1, f2)
  # echo $fp1
  # fp2.fromBigs(a1, a2)
  # echo $fp2

  echo $G2_CoFactorHigh
  echo $G2_CoFactorLow
  echo $G2_CoFactorShift

  var ctx: keccak256
  ctx.init()
  ctx.update(fromHex("6d657373616765"))
  var point = hashToG2(ctx, 0'u64)
  echo $point
