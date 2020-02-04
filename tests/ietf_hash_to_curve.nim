# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

import
  # Standard library
  unittest, strutils,
  # Internals
  ../blscurve/[common, milagro, hash_to_curve]

# Vectors for Hash to G2 curve of BLS12-381
# According to the IETF standard draft https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05

func hexToFP2(x, y: string): FP2_BLS381 =
  ## Convert a complex tuple x + iy to FP2
  # TODO: the result does not seem to need zero-initialization
  var xBig, yBig: BIG_384

  discard xBig.fromHex(x)
  discard yBig.fromHex(y)

  result.fromBigs(xBig, yBig)

proc toECP2(x, y: FP2_BLS381): ECP2_BLS381 =
  ## Create a point (x, y) on the G2 curve
  let onCurve = bool ECP2_BLS381_set(addr result, unsafeAddr x, unsafeAddr y)
  doAssert onCurve, "The coordinates (x, y) are not on the G2 curve"

template testHashToG2(constants: untyped) =
  ## Hash-to-curve "msg" and "dst" (domain separation tag)
  ## and compare the computed point
  ## with the expected point "ecp"
  proc testScenario() =
    # We create a proc to avoid allocating too many global variables
    constants

    let computedG2 = hashToG2(msg, dst)

    check: computedG2 == ecp

  testScenario()

suite "IETF Hash-to-Curve G2 BLS12-381":
  let dst = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO_POP_"

  test "Py-ECC #1 b'msg'":
    testHashToG2:
      let msg = "msg"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x07896efdac56b0f6cbd8c78841676d63fc733b692628687bf25273aa8a107bd8cb53bbdb705b551e239dffe019abd4df",
          y = "0x0bd557eda8d16ab2cb2e71cca4d7b343985064daad04734e07da5cdda26610b59cdc0810a25276467d24b315bf7860e0"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x001bdb6290cae9f30f263dd40f014b9f4406c3fbbc5fea47e2ebd45e42332553961eb53a15c09e5e090d7a7122dc6657",
          y = "0x18370459c44e799af8ef31634a683e340e79c3a06f912594d287a443620933b47a2a3e5ce4470539eae50f6d49b8ebd6"
        )
      )

  test "Py-ECC #2 b'01234567890123456789012345678901'":
    testHashToG2:
      let msg = "01234567890123456789012345678901"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x16b7456df1dfa411b8be80c503864b0795b0b9a7674c05c00e7bdee5a75cbdeec633e16a104406ea626ea6845f5d19b5",
          y = "0x12ae54eeb3b4dc113d7e80302e51456224087955910479929bf912d89177aa050376960002a96fc6541ac041957f4b93"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x1632fe9d91a984f30a7d9b3bab6583974a2ca55933d96cba85f39ddd61ea0129274f75ad7de29473adf3db676dcdb6a3",
          y = "0x08d5d3b670fca3661122b0ca5929e48f293a5a5c1261050c46b6a08eac3f7d1f5075e2139a63f98e717ecc7c2e00d042"
        )
      )

  # TODO: empty strings hashing
  # test "Py-ECC #3 ''":
  #   testHashToG2:
  #     let msg = ""
  #
  #     let ecp = toECP2(
  #       x = hexToFP2(
  #         # x = x' + iy'
  #         x = "0x0c38e18c9ca92ad387cbfa0e9bd62e53e4f938006097a092d5e9f2c6f3963d78969e7631bf8d6a8a9aad36bc82d763c1",
  #         y = "0x023ebc431b239ee7606aad7cd4eee60bb70df3e5072ede86946ffaddb0584e1fcfcee9484869f41e09ab4d64b9e4a72a"
  #       ),
  #       y = hexToFP2(
  #         # y = x'' + iy''
  #         x = "0x0735ae5ca4a2320d820e15501ee79c42ff58a6f40e8549eada554e07c94b34b6634b6034f8735a7e4ac01db81b00f58e",
  #         y = "0x1687b6a2fb9e542426d508d4a58846c0e3496ede2e12f57f3358110874ba0011e2107e0742eeb6707682d5ddf319b6f6"
  #       )
  #     )

  test "Py-ECC #4 b'abcdefghijklmnopqrstuvwxyz'":
    testHashToG2:
      let msg = "abcdefghijklmnopqrstuvwxyz"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x0db85d0c792c586c6efb4126e98a8a8788d28187a6432cbdd57444a8c937ce20e0fc0774477150d31bfff83a050b530e",
          y = "0x13505f5cbb1503c7b1206edd31364a467f5159d741cffe8f443f2282b4adfcf5f1450bd2fe6127991ff60955b3b40015"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x1738e4903e5618fcba965861c73d7c7a7544fabc9762ccdf9842dbba30566ce33047c3ff714ce8a10323bcac0ee88479",
          y = "0x0d0df337706a8b4c367ea189d9e213f47455399ddf734358695e84ad09630a724082ad22dda74e6cd41378dbb89b0ebd"
        )
      )

  test "Py-ECC #5 b'\\xFF' * 100":
    testHashToG2:
      let msg = "\xFF".repeat(100)

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x0a2b9bb7afda6e1c3cb2340aa679ce00469a14c651becd30fa231c83ab82d1b92db074058c3673daaaa2a113f0c3ea56",
          y = "0x0e7fcdf25cf4465f58de593bf6445ec1cd164de346a27ed46314dcbb35a830650f5bb4d8049878d9a84a34013fa4fb11"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x14f909c9fb9fb14c0e7455ed5306edaad40e7c57cdd719f59730db6ae64161db1f1a8159db4d97700fba7547920fe1a2",
          y = "0x1702a797d33e0c7b3fac012da0ef1960e0f4551f23ffee3e12dc36ac4acdd6d78bee97bad76689b8e70dac80449a626c"
        )
      )

  test "Py-ECC #6 b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'":
    testHashToG2:
      let msg = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x07e2b8b61562339640addfda3202f5d657aa77c143bf5bceda818525ba6f984eba2648528928d6c9680f752dd88d91e3",
          y = "0x1663cd7231bd9708bebe0be61baecf2b89ebaa658150696f5be2dbe0e092ec698c931e8795ac6319f1c5fdda5d14136a"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x033d40a6eb88c11c6018fcc00489bc4b9dd700c20d1bab21ad463c5ee63ce671d199020ba743828d450da050f0385680",
          y = "0x10336a533d1e3564da20bffe87ebc82121cfbfad2e36ecb950c5e12d8552bf932f5f5e846a50e9706b21b0db6585a777"
        )
      )

  test "Py-ECC #7 b'e46b320165eec91e6344fa10340d5b3208304d6cad29d0d5aed18466d1d9d80e'":
    testHashToG2:
      let msg = "e46b320165eec91e6344fa10340d5b3208304d6cad29d0d5aed18466d1d9d80e"

      let ecp = toECP2(
        x = hexToFP2(
          # x = x' + iy'
          x = "0x119a71e0d20489cf8c5f82c51e879e7b344e53307b53be650df7f3f04907b75b71fdafe26e8d4e14e603440b09efe6f3",
          y = "0x0e4ea193377da29537e8fe6f6f631adff10afaef2ea1eb2107d30d97358c1a19975e0a8bb62650ff90447cf5b3719c1d"
        ),
        y = hexToFP2(
          # y = x'' + iy''
          x = "0x1142f2e077cc4230ee3cf07565ee626141ea9b86a79a0422d7f0e84c281ca09c5bbbe95f21e51285618c81d6dfda943d",
          y = "0x015e4da056552343eb519b3087962521d112c7e307d731373e8f1c72415306ccbc3c14fc6d68d61d2feeda3ea2e7729f"
        )
      )
