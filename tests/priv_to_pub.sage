# Nim-BLSCurve
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
#  * MIT license ([LICENSE-MIT](LICENSE-MIT))
# at your option.
# This file may not be copied, modified, or distributed except according to
# those terms.

# Test case generator
# ------------------------------------------------------------------------------

# Parameters
# ------------------------------------------------------------------------------
x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16)
p = (x - 1)^2 * (x^4 - x^2 + 1)//3 + x
r = x^4 - x^2 + 1
cofactor = Integer('0x396c8c005555e1568c00aaab0000aaab')

# Effective cofactor for the G2 curve (that leads to equivalent hashToG2 when using endomorphisms)
g2_h_eff = Integer('0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551')

# Finite fields
Fp       = GF(p)
K2.<u>  = PolynomialRing(Fp)
Fp2.<beta>  = Fp.extension(u^2+1)
# K6.<v>  = PolynomialRing(Fp2)
# Fp6.<eta>  = Fp2.extension(v^3-Fp2([1, 1])
# K12.<w> = PolynomialRing(Fp6)
# K12.<gamma> = F6.extension(w^2-eta)

# Curves
b = 4
SNR = Fp2([1, 1])
G1 = EllipticCurve(Fp, [0, b])
G2 = EllipticCurve(Fp2, [0, b*SNR])

# Generator points
if False:
    P1 = G1.gen(0)
    (P1x, P1y, P1z) = P1
    print('P1x: ' + Integer(P1x).hex())
    print('P1y: ' + Integer(P1y).hex())
else:
    # https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-02#section-4.3.2
    P1 = G1(
        Integer('0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'),
        Integer('0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'),
        Integer(1)
    )

def priv_to_pub(scalar):
    return scalar * P1

def pointToString(P):
    (Px, Py, Pz) = P
    return '(x: ' + Integer(Px).hex() + ', y: ' + Integer(Py).hex() + ')'

def pointToCompressed(P):
    (Px, Py, Pz) = P
    rawX = Integer(Px)
    if Py > p - Py:
        rawX |= 1 << 381
    rawX |= 1 << 383
    return int(rawX).to_bytes(48, 'big').hex()

for i in range(1000, 1010):
    print('---------------------------------------')
    print(f'seckey: {i}')
    print(f'seckey hex: {i.to_bytes(32, "big").hex()}')
    pubkey = priv_to_pub(i)
    print(f'pubKey (uncompressed): {pointToString(pubkey)}')
    print(f'pubKey (compressed): {pointToCompressed(pubkey)}')

# ---------------------------------------
# seckey: 1000
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003e8
# pubKey (uncompressed): (x: 60e75190e62b6a54142d147289a735c4ce11a9d997543da539a3db57def5ed83ba40b74e55065f02b35aa1d504c404b, y: 17ecb08d4bb31b7eeb6581e6808c6abf58958845b917e085baaab098b9a8a3ecc8caf6f1a06c46b0f7812b09aa52e7a0)
# pubKey (compressed): a60e75190e62b6a54142d147289a735c4ce11a9d997543da539a3db57def5ed83ba40b74e55065f02b35aa1d504c404b
# ---------------------------------------
# seckey: 1001
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003e9
# pubKey (uncompressed): (x: e12039459c60491672b6a6282355d8765ba6272387fb91a3e9604fa2a81450cf16b870bb446fc3a3e0a187fff6f8945, y: 18b6c1ed9f45d3cbc0b01b9d038dcecacbd702eb26469a0eb3905bd421461712f67f782b4735849644c1772c93fe3d09)
# pubKey (compressed): ae12039459c60491672b6a6282355d8765ba6272387fb91a3e9604fa2a81450cf16b870bb446fc3a3e0a187fff6f8945
# ---------------------------------------
# seckey: 1002
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003ea
# pubKey (uncompressed): (x: 147b327c8a15b39634a426af70c062b50632a744eddd41b5a4686414ef4cd9746bb11d0a53c6c2ff21bbcf331e07ac92, y: 78c2e9782fa5d9ab4e728684382717aa2b8fad61b5f5e7cf3baa0bc9465f57342bb7c6d7b232e70eebcdbf70f903a45)
# pubKey (compressed): 947b327c8a15b39634a426af70c062b50632a744eddd41b5a4686414ef4cd9746bb11d0a53c6c2ff21bbcf331e07ac92
# ---------------------------------------
# seckey: 1003
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003eb
# pubKey (uncompressed): (x: 5fc4ae543ca162474586e76d72c47d0151c3cb7b77e82c87e554abf72548e2e746bc675805b688b5016269e18ff4250, y: 7c13f661fd28bf1ea1cf51c762dda21547877eedf54e9263b3b5d0923820b58ed81503beb24fc4cd50bd47d9d67d7e)
# pubKey (compressed): 85fc4ae543ca162474586e76d72c47d0151c3cb7b77e82c87e554abf72548e2e746bc675805b688b5016269e18ff4250
# ---------------------------------------
# seckey: 1004
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003ec
# pubKey (uncompressed): (x: caa0de862793e567c6050aa822db2d6cb2b520bc62b6dbcba7e773067ed09c7ba0282d7c20e01500c6c2fa76408aded, y: c7c359be46db8efd81618b29cea252fdbfff8229dd3e3c7f98c10801fdc9bb65403d124b43a934f8a1cf8ca351ee1df)
# pubKey (compressed): 8caa0de862793e567c6050aa822db2d6cb2b520bc62b6dbcba7e773067ed09c7ba0282d7c20e01500c6c2fa76408aded
# ---------------------------------------
# seckey: 1005
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003ed
# pubKey (uncompressed): (x: a273fd05323e1381e10e93e683c34647328127020b3507fc8cddc337038e33fbd7a99ef0d2c7b6a278d7f8116162560, y: 134e59e38d0cdda7464634c997d9f08b7e336bdfa895b764f8c4e24e52e3f46683d8e798ada2d65f055adb4a7bf6c279)
# pubKey (compressed): aa273fd05323e1381e10e93e683c34647328127020b3507fc8cddc337038e33fbd7a99ef0d2c7b6a278d7f8116162560
# ---------------------------------------
# seckey: 1006
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003ee
# pubKey (uncompressed): (x: fcecff9ae0490f723123822c66f36996d237490d6769ee68f9f7a7da1c6bac8b5c3d0c4348e8ce8fc3d5159f8333484, y: 86e75481cf86317947ced9b0c52a631a22a213e49b9ea0cd016184d48541e9f2424a5e01a800673b7a2b2601cb77bea)
# pubKey (compressed): 8fcecff9ae0490f723123822c66f36996d237490d6769ee68f9f7a7da1c6bac8b5c3d0c4348e8ce8fc3d5159f8333484
# ---------------------------------------
# seckey: 1007
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003ef
# pubKey (uncompressed): (x: f4ffe81a50cf117069c9a66ad9f2776eeeae94fe02ba2a0f9596cb798f9e5bdf4719fceaa61746ffe2408f25b56d96e, y: 326c5937def2d0725be78d653b1e107c8faf40fea0759caf640ae0be5c569ef73ecdcc1d8552725f8de69e95f4cf53c)
# pubKey (compressed): 8f4ffe81a50cf117069c9a66ad9f2776eeeae94fe02ba2a0f9596cb798f9e5bdf4719fceaa61746ffe2408f25b56d96e
# ---------------------------------------
# seckey: 1008
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003f0
# pubKey (uncompressed): (x: 785405f275ee2fd934e83835a79ba651f80b0f432df1b806350dc949c169c60e60767e41faed8eaac5ed0e9e210787c, y: c82aaba7cb0db559d0eb9cb1bebb8d9de2ac1bbceda92518b16bdca4be5bda5b219b345ec2b3719fac5891eb3ee531a)
# pubKey (compressed): 8785405f275ee2fd934e83835a79ba651f80b0f432df1b806350dc949c169c60e60767e41faed8eaac5ed0e9e210787c
# ---------------------------------------
# seckey: 1009
# seckey hex: 00000000000000000000000000000000000000000000000000000000000003f1
# pubKey (uncompressed): (x: ade2091378293a63d55328cef23736f4dbdc49bd3c0787b8c18cd6a8ddc2d42a279242e87b22d1909f3f1d55e5da66, y: 14f22ce1b5483fa15b71f81d998cbb695a369948214bf7d7c9841c26903cee7b5485bc1331061f1c9c17cce8778b15e)
# pubKey (compressed): 80ade2091378293a63d55328cef23736f4dbdc49bd3c0787b8c18cd6a8ddc2d42a279242e87b22d1909f3f1d55e5da66
