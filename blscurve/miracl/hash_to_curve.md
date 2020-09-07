# BLS12-381 Hash-to-G2 Curve

This document extracts part of the draft standard for hash-to-G2 implementation
for the BLS12-381 pairing-friendly elliptic curve.

Hash to Elliptic curve implementation for BLS12-381.
- IETF Standard Draft: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07
  - Formatted HTML version: https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.html
- IETF Implementation: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
  - The following can be used as a test vector generator:
    https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/draft-irtf-cfrg-hash-to-curve-07/poc/suite_bls12381g2.sage
- Ethereum Foundation implementation: https://github.com/ethereum/py_ecc
  - Specific PRs:
    - v5: https://github.com/ethereum/py_ecc/pull/83/files
    - v6: https://github.com/ethereum/py_ecc/pull/87
    - v7: https://github.com/ethereum/py_ecc/pull/94

> The Hash-To-Curve v7 is binary compatible with Hash-To-Curve v9
> They only differ by cosmetic changes like naming, see
> https://tools.ietf.org/rfcdiff?url1=https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.txt&url2=https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-09.txt

hash_to_curve
----------------------------------------------------------------------
Section 3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-3

This section presents a general framework for encoding byte strings to
points on an elliptic curve.  To construct these encodings, we rely
on three basic functions:

*  The function hash_to_field, {0, 1}^* x {1, 2, ...} -> (F, F, ...),
   arbitrary-length byte strings to a list of one or more
   elements of a finite field; its implementation is defined in
   Section 5.

*  The function map_to_curve, F -> E, calculates a point on the
   elliptic curve E from an element of the finite field F over which
   E is defined.  Section 6 describes mappings for a range of curve
   families.

*  The function clear_cofactor, E -> G, sends any point on the curve
   E to the subgroup G of E.  Section 7 describes methods to perform
   this operation.

\[...\] Overview of encode_to_curve which is for non-uniform encoding (NU suites), faster but can be distinguished from a random oracle.
Not suitable for Ethereum 2.

Random oracle encoding (hash_to_curve).
  This function encodes byte strings to points in G.
  This function is suitable for applications requiring
  a random oracle returning points in G provided that
  map_to_curve is "well distributed" (\[FFSTV13\], Def. 1).  All of
  the map_to_curve functions defined in Section 6 meet this
  requirement.

  hash_to_curve(msg)

  Input: msg, an arbitrary-length byte string.
  Output: P, a point in G.

  Steps:
  1. u = hash_to_field(msg, 2)
  2. Q0 = map_to_curve(u[0])
  3. Q1 = map_to_curve(u[1])
  4. R = Q0 + Q1      // point addition
  5. P = clear_cofactor(R)
  6. return P

  Instances of these functions are given in Section 8, which defines a
  list of suites that specify a full set of parameters matching
  elliptic curves and algorithms.

hash_to_field
----------------------------------------------------------------------
Section 5.2 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-5.2

The following procedure implements hash\_to\_field.

The expand\_message parameter to this function MUST conform to the requirements
given below ({{hashtofield-expand}}).

{{domain-separation}} discusses requirements for domain separation and
recommendations for choosing DST, the domain separation tag.
This is the REQUIRED method for applying domain separation.

~~~
hash_to_field(msg, count)

Parameters:
- DST, a domain separation tag (see discussion above).
- F, a finite field of characteristic p and order q = p^m.
- p, the characteristic of F (see immediately above).
- m, the extension degree of F, m >= 1 (see immediately above).
- L = ceil((ceil(log2(p)) + k) / 8), where k is the security
  parameter of the suite (e.g., k = 128).
- expand_message, a function that expands a byte string and
  domain separation tag into a pseudorandom byte string
  (see discussion above).

Inputs:
- msg is a byte string containing the message to hash.
- count is the number of elements of F to output.

Outputs:
- (u_0, ..., u_(count - 1)), a list of field elements.

Steps:
1. len_in_bytes = count * m * L
2. pseudo_random_bytes = expand_message(msg, DST, len_in_bytes)
3. for i in (0, ..., count - 1):
4.   for j in (0, ..., m - 1):
5.     elm_offset = L * (j + i * m)
6.     tv = substr(pseudo_random_bytes, elm_offset, L)
7.     e_j = OS2IP(tv) mod p
8.   u_i = (e_0, ..., e_(m - 1))
9. return (u_0, ..., u_(count - 1))
~~~

> 🛈 Note:
>
>   I2OSP and OS2IP: These primitives are used to convert an octet string to
>   and from a non-negative integer as described in RFC8017.
>   https://tools.ietf.org/html/rfc8017#section-4
>
>   In summary those are bigEndian <-> integer conversion routine with the following signatures
>   - proc I2OSP(n: BigInt, resultLen: Natural): string
>   - proc OS2IP(s: string): BigInt

expand_message
----------------------------------------------------------------------

expand\_message is a function that generates a pseudorandom byte string.
It takes three arguments:

- msg, a byte string containing the message to hash,
- DST, a byte string that acts as a domain separation tag, and
- len\_in\_bytes, the number of bytes to be generated.

> 🛈 Note:
>
>   There are 2 expand_messages variants, we only implement the expand_message_xmd variant
>   for use with SHA2-256

~~~
expand_message_xmd(msg, DST, len_in_bytes)

Parameters:
- H, a hash function (see requirements above).
- b_in_bytes, ceil(b / 8) for b the output size of H in bits.
  For example, for b = 256, b_in_bytes = 32.
- r_in_bytes, the input block size of H, measured in bytes.
  For example, for SHA-256, r_in_bytes = 64.

Input:
- msg, a byte string.
- DST, a byte string of at most 255 bytes.
  See below for information on using longer DSTs.
- len_in_bytes, the length of the requested output in bytes.

Output:
- pseudo_random_bytes, a byte string

Steps:
1.  ell = ceil(len_in_bytes / b_in_bytes)
2.  ABORT if ell > 255
3.  DST_prime = DST || I2OSP(len(DST), 1)
4.  Z_pad = I2OSP(0, r_in_bytes)
5.  l_i_b_str = I2OSP(len_in_bytes, 2)
6.  b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
7.  b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
8.  for i in (2, ..., ell):
9.    b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
10. pseudo_random_bytes = b_1 || ... || b_ell
11. return substr(pseudo_random_bytes, 0, len_in_bytes)
~~~

Note that the string Z\_pad is prepended to msg when computing b\_0 (step 6).
This is necessary for security when H is a Merkle-Damgaard hash, e.g., SHA-2
(see {{security-considerations-expand-xmd}}).
Hashing this additional data means that the cost of computing b\_0 is higher
than the cost of simply computing H(msg).
In most settings this overhead is negligible, because the cost of evaluating
H is much less than the other costs involved in hashing to a curve.

It is possible, however, to entirely avoid this overhead by taking advantage
of the fact that Z\_pad depends only on H, and not on the arguments to
expand\_message\_xmd.
To do so, first precompute and save the internal state of H after ingesting
Z\_pad; and then, when computing b\_0, initialize H using the saved state.
Further details are beyond the scope of this document.

map_to_curve
----------------------------------------------------------------------
6.6.2.  Simplified Shallue-van de Woestijne-Ulas Method for AB == 0 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-6.6.2

> Wahby, R. and D. Boneh,
>
> "Fast and simple constant-time hashing to the BLS12-381 elliptic curve",
>
> Technical report ePrint 2019/403, 2019,
> <https://eprint.iacr.org/2019/403>

> 🛈 Note:
>
>    Pairing-Friendly curve have A == 0 in Weierstrass curve equation
>      y² = x³ + A * x + B
>    and so can't use the straight simplified SWU method from 6.6.2, see chapter 6.6.3

_Simplified Shallue-van de Woestijne-Ulas Method for pairing-friendly curves_

Explanation
1. find a curve E' that is isogenous to the target curve E
   E' parametrized by y² = g'(x) = x³ + A' * x + B'
2. Then isogeny map E' => E

Operations:

~~~
1. (x', y') = map_to_curve_simple_swu(u)    # (x', y') is on E'
2.   (x, y) = iso_map(x', y')               # (x, y) is on E
3. return (x, y)
~~~

simplified_swu
----------------------------------------------------------------------
6.6.2. Simplified SWU -  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#section-6.6.2

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
Appendix C.3

The 3-isogeny map from (x', y') on E' to (x, y) on E is given by the following rational functions:

* x = x\_num / x\_den, where
  - x\_num = k\_(1,3) * x'^3 + k\_(1,2) * x'^2 + k\_(1,1) * x' + k\_(1,0)
  - x\_den = x'^2 + k\_(2,1) * x' + k\_(2,0)

* y = y' * y\_num / y\_den, where
  - y\_num = k\_(3,3) * x'^3 + k\_(3,2) * x'^2 + k\_(3,1) * x' + k\_(3,0)
  - y\_den = x'^3 + k\_(4,2) * x'^2 + k\_(4,1) * x' + k\_(4,0)

The constants used to compute x\_num are as follows:

* k\_(1,0) = 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 + 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6 * I
* k\_(1,1) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a * I
* k\_(1,2) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e + 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d * I
* k\_(1,3) = 0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1

The constants used to compute x\_den are as follows:

* k\_(2,0) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63 * I
* k\_(2,1) = 0xc + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f * I

The constants used to compute y\_num are as follows:

* k\_(3,0) = 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706 + 0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706 * I
* k\_(3,1) = 0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be * I
* k\_(3,2) = 0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c + 0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f * I
* k\_(3,3) = 0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10

The constants used to compute y\_den are as follows:

* k\_(4,0) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb * I
* k\_(4,1) = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3 * I
* k\_(4,2) = 0x12 + 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99 * I

Clear cofactor
----------------------------------------------------------------------
Section 7

The mappings of Section 6 always output a point on the elliptic
curve, i.e., a point in a group of order h * r (Section 2.1).
Obtaining a point in G may require a final operation commonly called
"clearing the cofactor," which takes as input any point on the curve.

The cofactor can always be cleared via scalar multiplication by h.
For elliptic curves where h = 1, i.e., the curves with a prime number
of points, no operation is required.  This applies, for example, to
the NIST curves P-256, P-384, and P-521 \[FIPS186-4\].

In some cases, it is possible to clear the cofactor via a faster
method than scalar multiplication by h.  These methods are equivalent
to (but usually faster than) multiplication by some scalar h_eff
whose value is determined by the method and the curve.  Examples of
fast cofactor clearing methods include the following:

*  For certain pairing-friendly curves having subgroup G2 over an
  extension field, Scott et al.  \[SBCDK09\] describe a method for
  fast cofactor clearing that exploits an efficiently-computable
  endomorphism.  Fuentes-Castaneda et al.  \[FKR11\] propose an
  alternative method that is sometimes more efficient.  Budroni and
  Pintore \[BP17\] give concrete instantiations of these methods for
  Barreto-Lynn-Scott pairing-friendly curves \[BLS03\]. This method
 	is described for the specific case of BLS12-381 in Appendix D.4.

*  Wahby and Boneh (\[WB19\], Section 5) describe a trick due to Scott
  for fast cofactor clearing on any elliptic curve for which the
  prime factorization of h and the structure of the elliptic curve
  group meet certain conditions.

The clear_cofactor function is parameterized by a scalar h_eff.
Specifically,

    clear_cofactor(P) := h_eff * P

where * represents scalar multiplication.  When a curve does not
support a fast cofactor clearing method, h_eff = h and the cofactor
MUST be cleared via scalar multiplication.

When a curve admits a fast cofactor clearing method, clear_cofactor
MAY be evaluated either via that method or via scalar multiplication
by the equivalent h_eff; these two methods give the same result.
Note that in this case scalar multiplication by the cofactor h does
not generally give the same result as the fast method, and SHOULD NOT
be used.

BLS 12-381 suite
----------------------------------------------------------------------
Section 8.8.2

> 🛈 Note:
> ETH2 uses the "Random Oracle" suite


BLS12381G2\_XMD:SHA-256\_SSWU\_RO\_ is defined as follows:

- encoding type: hash\_to\_curve (Section 3)
- E: y^2 = x^3 + 4 * (1 + I)
- base field F is GF(p^m), where
  - p: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
  - m: 2
  - (1, I) is the basis for F, where I^2 + 1 == 0 in F
- k: 128
- expand\_message: expand\_message\_xmd (Section 5.3.1)
- H: SHA-256
- L: 64
- f: Simplified SWU for AB == 0, Section 6.6.3
- Z: -(2 + I)
- E': y'^2 = x'^3 + A' * x' + B', where
  - A' = 240 * I
  - B' = 1012 * (1 + I)
- iso\_map: the isogeny map from E' to E given in Appendix C.3
- h\_eff: 0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551

Note that the h\_eff values for these suites are chosen for compatibility
with the fast cofactor clearing method described by
Budroni and Pintore (\[BP17\]), Section 4.1), and summarized in Appendix D.4.

An optimized example implementation of the Simplified SWU mapping
to the curve E' isogenous to BLS12-381 G2 is given in Appendix D.2.3.


Optimized simple SWU
----------------------------------------------------------------------

D.2.3.  q = 9 (mod 16)

The following is a straight-line implementation of the Simplified SWU
mapping that applies to any curve over GF(q) where q = 9 (mod 16).
This includes the curve isogenous to BLS12-381 G2 (Section 8.8.2).

map_to_curve_simple_swu_9mod16(u)

Input: u, an element of F.
Output: (xn, xd, yn, yd) such that (xn / xd, yn / yd) is a
        point on the target curve.

Constants:
1. c1 = (q - 9) / 16            # Integer arithmetic
2. c2 = sqrt(-1)
3. c3 = sqrt(c2)
4. c4 = sqrt(Z^3 / c3)
5. c5 = sqrt(Z^3 / (c2 * c3))

Steps:
1.  tv1 = u^2
2.  tv3 = Z * tv1
3.  tv5 = tv3^2
4.   xd = tv5 + tv3
5.  x1n = xd + 1
6.  x1n = x1n * B
7.   xd = -A * xd
8.   e1 = xd == 0
9.   xd = CMOV(xd, Z * A, e1)   # If xd == 0, set xd = Z * A
10. tv2 = xd^2
11. gxd = tv2 * xd              # gxd == xd^3
12. tv2 = A * tv2
13. gx1 = x1n^2
14. gx1 = gx1 + tv2             # x1n^2 + A * xd^2
15. gx1 = gx1 * x1n             # x1n^3 + A * x1n * xd^2
16. tv2 = B * gxd
17. gx1 = gx1 + tv2             # x1n^3 + A * x1n * xd^2 + B * xd^3
18. tv4 = gxd^2
19. tv2 = tv4 * gxd             # gxd^3
20. tv4 = tv4^2                 # gxd^4
21. tv2 = tv2 * tv4             # gxd^7
22. tv2 = tv2 * gx1             # gx1 * gxd^7
23. tv4 = tv4^2                 # gxd^8
24. tv4 = tv2 * tv4             # gx1 * gxd^15
25.   y = tv4^c1                # (gx1 * gxd^15)^((q - 9) / 16)
26.   y = y * tv2               # This is almost sqrt(gx1)
27. tv4 = y * c2                # check the four possible sqrts
28. tv2 = tv4^2
29. tv2 = tv2 * gxd
30.  e2 = tv2 == gx1
31.   y = CMOV(y, tv4, e2)
32. tv4 = y * c3
33. tv2 = tv4^2
34. tv2 = tv2 * gxd
35.  e3 = tv2 == gx1
36.   y = CMOV(y, tv4, e3)
37. tv4 = tv4 * c2
38. tv2 = tv4^2
39. tv2 = tv2 * gxd
40.  e4 = tv2 == gx1
41.   y = CMOV(y, tv4, e4)      # if x1 is square, this is its sqrt
42. gx2 = gx1 * tv5
43. gx2 = gx2 * tv3             # gx2 = gx1 * Z^3 * u^6
44. tv5 = y * tv1
45. tv5 = tv5 * u               # This is almost sqrt(gx2)
46. tv1 = tv5 * c4              # check the four possible sqrts
47. tv4 = tv1 * c2
48. tv2 = tv4^2
49. tv2 = tv2 * gxd
50.  e5 = tv2 == gx2
51. tv1 = CMOV(tv1, tv4, e5)
52. tv4 = tv5 * c5
53. tv2 = tv4^2
54. tv2 = tv2 * gxd
55.  e6 = tv2 == gx2
56. tv1 = CMOV(tv1, tv4, e6)
57. tv4 = tv4 * c2
58. tv2 = tv4^2
59. tv2 = tv2 * gxd
60.  e7 = tv2 == gx2
61. tv1 = CMOV(tv1, tv4, e7)
62. tv2 = y^2
63. tv2 = tv2 * gxd
64.  e8 = tv2 == gx1
65.   y = CMOV(tv1, y, e8)      # choose correct y-coordinate
66. tv2 = tv3 * x1n             # x2n = x2n / xd = Z * u^2 * x1n / xd
67.  xn = CMOV(tv2, x1n, e8)    # choose correct x-coordinate
68.  e9 = sgn0(u) == sgn0(y)    # Fix sign of y
69.   y = CMOV(-y, y, e9)
70. return (xn, xd, y, 1)
