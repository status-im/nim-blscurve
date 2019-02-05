#ifndef CONFIG_CURVE_BLS381_H
#define CONFIG_CURVE_BLS381_H

#include"amcl.h"
#include"config_field_BLS381.h"

// ECP stuff

#define CURVETYPE_BLS381 WEIERSTRASS
#define PAIRING_FRIENDLY_BLS381 BLS
#define CURVE_SECURITY_BLS381 128


#if PAIRING_FRIENDLY_BLS381 != NOT
//#define USE_GLV_BLS381	  /**< Note this method is patented (GLV), so maybe you want to comment this out */
//#define USE_GS_G2_BLS381 /**< Well we didn't patent it :) But may be covered by GLV patent :( */
#define USE_GS_GT_BLS381 /**< Not patented, so probably safe to always use this */

#define POSITIVEX 0
#define NEGATIVEX 1

#define SEXTIC_TWIST_BLS381 M_TYPE
#define SIGN_OF_X_BLS381 NEGATIVEX

#endif

#if CURVE_SECURITY_BLS381 == 128
#define AESKEY_BLS381 16 /**< Symmetric Key size - 128 bits */
#define HASH_TYPE_BLS381 SHA256  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS381 == 192
#define AESKEY_BLS381 24 /**< Symmetric Key size - 192 bits */
#define HASH_TYPE_BLS381 SHA384  /**< Hash type */
#endif

#if CURVE_SECURITY_BLS381 == 256
#define AESKEY_BLS381 32 /**< Symmetric Key size - 256 bits */
#define HASH_TYPE_BLS381 SHA512  /**< Hash type */
#endif



#endif
