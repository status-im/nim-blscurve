# BLS12-381 Hash-to-G2 Curve

This document extracts part of the draft standard for hash-to-G2 implementation
for the BLS12-381 pairing-friendly elliptic curve.

Hash to Elliptic curve implementation for BLS12-381.
- IETF Standard Draft: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
  - Formatted HTML version: https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.html
- IETF Implementation: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
  - The following can be used as a test vector generator:
    https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/6cf7fa97/poc/suite_bls12381g2.sage
- Ethereum Foundation implementation: https://github.com/ethereum/py_ecc
  - Specific PR: https://github.com/ethereum/py_ecc/pull/83/files

hash_to_curve
----------------------------------------------------------------------
Section 3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-3

This section presents a general framework for encoding bit strings to
points on an elliptic curve.  To construct these encodings, we rely
on three basic functions:

o  The function hash_to_base, {0, 1}^* x {0, 1, 2} -> F, hashes
   arbitrary-length bit strings to elements of a finite field; its
   implementation is defined in Section 5.

o  The function map_to_curve, F -> E, calculates a point on the
   elliptic curve E from an element of the finite field F over which
   E is defined.  Section 6 describes mappings for a range of curve
   families.

o  The function clear_cofactor, E -> G, sends any point on the curve
   E to the subgroup G of E.  Section 7 describes methods to perform
   this operation.

[...] (Overview of encode_to_curve)

Random oracle encoding (hash_to_curve).
  This function encodes bitstrings to points in G.
  The distribution of the output is
  indistinguishable from uniformly random in G provided that
  map_to_curve is "well distributed" (\[FFSTV13\], Def. 1).  All of
  the map_to_curve functions defined in Section 6 meet this
  requirement.

  hash_to_curve(alpha)

  Input: alpha, an arbitrary-length bit string.
  Output: P, a point in G.

  Steps:
  1. u0 = hash_to_base(alpha, 0)
  2. u1 = hash_to_base(alpha, 1)
  3. Q0 = map_to_curve(u0)
  4. Q1 = map_to_curve(u1)
  5. R = Q0 + Q1      // point addition
  6. P = clear_cofactor(R)
  7. return P

  Instances of these functions are given in Section 8, which defines a
  list of suites that specify a full set of parameters matching
  elliptic curves and algorithms.

hash_to_base
----------------------------------------------------------------------
Section 5.3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-5.3

The following procedure implements hash_to_base.

hash_to_base(msg, ctr)

Parameters:
- DST, a domain separation tag (see discussion above).
- H, a cryptographic hash function.
- F, a finite field of characteristic p and order q = p^m.
- L = ceil((ceil(log2(p)) + k) / 8), where k is the security
  parameter of the cryptosystem (e.g., k = 128).
- HKDF-Extract and HKDF-Expand are as defined in RFC5869,
  instantiated with the hash function H.

Inputs:
- msg is the message to hash.
- ctr is 0, 1, or 2.
  This is used to efficiently create independent
  instances of hash_to_base (see discussion above).

Output:
- u, an element in F.

Steps:
1. m' = HKDF-Extract(DST, msg)
2. for i in (1, ..., m):
3.   info = "H2C" || I2OSP(ctr, 1) || I2OSP(i, 1)
4.   t = HKDF-Expand(m', info, L)
5.   e_i = OS2IP(t) mod p
6. return u = (e_1, ..., e_m)

> ⚠️ Important:
>   in the invocation of HKDF-Extract, the message is
>   the message is appended with a null-byte
>
>   Section 5.1
>   > Finally, hash_to_base appends one zero byte to msg in the invocation
>   > of HKDF-Extract. This ensures that the use of HKDF in hash_to_base
>   > This ensures that the use of HKDF in hash_to_base
>   > is indifferentiable from a random oracle (see \[LBB19\], Lemma 8 and
>   > \[DRST12\], Theorems 4.3 and 4.4).  (In particular, this approach works
>   > because it ensures that the final byte of each HMAC invocation in
>   > HKDF-Extract and HKDF-Expand is distinct.)

> 🛈 Note:
>
>   I2OSP and OS2IP: These primitives are used to convert an octet string to
>   and from a non-negative integer as described in RFC8017.
>   https://tools.ietf.org/html/rfc8017#section-4
>
>   In summary those are bigEndian <-> integer conversion routine with the following signatures
>   - proc I2OSP(n: BigInt, resultLen: Natural): string
>   - proc OS2IP(s: string): BigInt


map_to_curve
----------------------------------------------------------------------
6.9.2.  Simplified SWU for Pairing-Friendly Curves - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.9.2

_Simplified Shallue-van de Woestijne-Ulas Method for pairing-friendly curves_

> Wahby, R. and D. Boneh,
>
> "Fast and simple constant-time hashing to the BLS12-381 elliptic curve",
>
> Technical report ePrint 2019/403, 2019,
> <https://eprint.iacr.org/2019/403>

Explanation
1. find a curve E' that is isogenous to the target curve E
   E' parametrized by y^2 = g'(x) = x^3 + A' * x + B'
2. Then isogeny map E' => E

Step 1 follows the simplified SWU method 6.5.2
(Simplified Shallue-van de Woestijne-Ulas Method)

Step 2 BLS12-381 isogeny map is detailed in Appendix C.2https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#appendix-C.2

simplified_swu
----------------------------------------------------------------------
6.5.2. Simplified SWU -  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.5.2

_Simplified Shallue-van de Woestijne-Ulas Method_

> Brier, E., Coron, J., Icart, T., Madore, D., Randriam, H., and M. Tibouchi
>
> "Efficient Indifferentiable Hashing into Ordinary Elliptic Curves",
>
> In Advances in Cryptology - CRYPTO 2010, pages 237-254,
>
> DOI 10.1007/978-3-642-14623-7_13, 2010,
> <https://doi.org/10.1007/978-3-642-14623-7_13>.

Preconditions: A Weierstrass curve y^2 = x^3 + A * x + B where A != 0 and B != 0.

Constants:

- A and B, the parameters of the Weierstrass curve.

- Z, an element of F meeting the below criteria.
  1. Z is non-square in F,
  2. Z != -1 in F,
  3. the polynomial g(x) - Z is irreducible over F, and
  4. g(B / (Z * A)) is square in F.

Sign of y: Inputs u and -u give the same x-coordinate.
Thus, we set sgn0(y) == sgn0(u).

Exceptions: The exceptional cases are values of u such that
Z^2 * u^4 + Z * u^2 == 0. This includes u == 0, and may include
other values depending on Z. Implementations must detect
this case and set x1 = B / (Z * A), which guarantees that g(x1)
is square by the condition on Z given above.

Operations:

1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
2.  x1 = (-B / A) * (1 + tv1)
3.  If tv1 == 0, set x1 = B / (Z * A)
4. gx1 = x1^3 + A * x1 + B
5.  x2 = Z * u^2 * x1
6. gx2 = x2^3 + A * x2 + B
7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
8.  Else set x = x2 and y = sqrt(gx2)
9.  If sgn0(u) != sgn0(y), set y = -y
10. return (x, y)

Implementation

> 🛈 This is a constant-time implementation

The following procedure implements the simplified SWU mapping in a straight-line fashion.
Appendix D gives an optimized straight-line procedure for P-256.
For more information on optimizing this mapping, see
Wahby and Boneh Section 4 or the example code found at [hash2curve-repo](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve).

~~~
map_to_curve_simple_swu(u)
Input: u, an element of F.
Output: (x, y), a point on E.

Constants:
1.  c1 = -B / A
2.  c2 = -1 / Z

Steps:
1.  tv1 = Z * u^2
2.  tv2 = tv1^2
3.   x1 = tv1 + tv2
4.   x1 = inv0(x1)
5.   e1 = x1 == 0
6.   x1 = x1 + 1
7.   x1 = CMOV(x1, c2, e1)    # If (tv1 + tv2) == 0, set x1 = -1 / Z
8.   x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
9.  gx1 = x1^2
10. gx1 = gx1 + A
11. gx1 = gx1 * x1
12. gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
13.  x2 = tv1 * x1            # x2 = Z * u^2 * x1
14. tv2 = tv1 * tv2
15. gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
16.  e2 = is_square(gx1)
17.   x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
18.  y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
19.   y = sqrt(y2)
20.  e3 = sgn0(u) == sgn0(y)  # Fix sign of y
21.   y = CMOV(-y, y, e3)
22. return (x, y)
~~~


3-isogeny map for BLS12-381 G2
----------------------------------------------------------------------
Appendix C.2

The 3-isogeny map from (x', y') on E' to (x, y) on E is given by the following rational functions:

- x = x\_num / x\_den, where
  - x\_num = k\_(1,3) * x'^3 + k\_(1,2) * x'^2 + k\_(1,1) * x' + k\_(1,0)
  - x\_den = x'^2 + k\_(2,1) * x' + k\_(2,0)

- y = y' * y\_num / y\_den, where
  - y\_num = k\_(3,3) * x'^3 + k\_(3,2) * x'^2 + k\_(3,1) * x' + k\_(3,0)
  - y\_den = x'^3 + k\_(4,2) * x'^2 + k\_(4,1) * x' + k\_(4,0)

The constants used to compute x\_num are as follows:

- k\_(1,0) = 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 + 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 * I
- k\_(1,1) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a * I
- k\_(1,2) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e + 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d * I
- k\_(1,3) = 0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1

The constants used to compute x\_den are as follows:

- k\_(2,0) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63 * I
- k\_(2,1) = 0xc + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f * I

The constants used to compute y\_num are as follows:

- k\_(3,0) = 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706 + 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706 * I
- k\_(3,1) = 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be * I
- k\_(3,2) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c + 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f * I
- k\_(3,3) = 0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10

The constants used to compute y\_den are as follows:

- k\_(4,0) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb * I
- k\_(4,1) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3 * I
- k\_(4,2) = 0x12 + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99 * I
