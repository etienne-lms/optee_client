// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <pkcs11_ta.h>
#include <stdio.h>
#include <string.h>

#include "ck_helpers.h"
#include "local_utils.h"

/*
 * PKCS11 TA returns Cryptoki like information structure.
 * These routine convert the PKCS11 TA format structure and bit flags
 * from/into Cryptoki format structures and bit flags.
 */
#define MEMCPY_FIELD(_dst, _src, _f) \
	do { \
		memcpy((_dst)->_f, (_src)->_f, sizeof((_dst)->_f)); \
		if (sizeof((_dst)->_f) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

#define MEMCPY_VERSION(_dst, _src, _f) \
	do { \
		memcpy(&(_dst)->_f, (_src)->_f, sizeof(CK_VERSION)); \
		if (sizeof(CK_VERSION) != sizeof((_src)->_f)) \
			return CKR_GENERAL_ERROR; \
	} while (0)

static CK_RV ta2ck_all_slot_flags(CK_SLOT_INFO_PTR ck_info,
				   struct pkcs11_slot_info *ta_info)
{
	CK_FLAGS ck_flag;
	uint32_t ta_mask;

	ck_info->flags = 0;
	for (ta_mask = 1; ta_mask; ta_mask <<= 1) {

		/* Skip TA token flags without a CK equilavent */
		if (ta2ck_slot_flag(&ck_flag, ta_mask))
			continue;

		if (ta_info->flags & ta_mask)
			ck_info->flags |= ck_flag;
	}

	return CKR_OK;
}

CK_RV ta2ck_slot_info(CK_SLOT_INFO_PTR ck_info,
			struct pkcs11_slot_info *ta_info)
{
	CK_RV rv;

	MEMCPY_FIELD(ck_info, ta_info, slotDescription);
	MEMCPY_FIELD(ck_info, ta_info, manufacturerID);

	rv = ta2ck_all_slot_flags(ck_info, ta_info);
	if (rv)
		return rv;

	MEMCPY_VERSION(ck_info, ta_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, ta_info, firmwareVersion);

	return CKR_OK;
}

static CK_RV ta2ck_all_token_flags(CK_TOKEN_INFO_PTR ck_info,
				struct pkcs11_token_info *ta_info)
{
	CK_FLAGS ck_flag;
	uint32_t ta_mask;

	ck_info->flags = 0;
	for (ta_mask = 1; ta_mask; ta_mask <<= 1) {

		/* Skip PKCS11 TA token flags without a CK equilavent */
		if (ta2ck_token_flag(&ck_flag, ta_mask))
			continue;

		if (ta_info->flags & ta_mask)
			ck_info->flags |= ck_flag;
	}

	return CKR_OK;
}

CK_RV ta2ck_token_info(CK_TOKEN_INFO_PTR ck_info,
			struct pkcs11_token_info *ta_info)
{
	CK_RV rv;

	MEMCPY_FIELD(ck_info, ta_info, label);
	MEMCPY_FIELD(ck_info, ta_info, manufacturerID);
	MEMCPY_FIELD(ck_info, ta_info, model);
	MEMCPY_FIELD(ck_info, ta_info, serialNumber);

	rv = ta2ck_all_token_flags(ck_info, ta_info);
	if (rv)
		return rv;

	ck_info->ulMaxSessionCount = ta_info->ulMaxSessionCount;
	ck_info->ulSessionCount = ta_info->ulSessionCount;
	ck_info->ulMaxRwSessionCount = ta_info->ulMaxRwSessionCount;
	ck_info->ulRwSessionCount = ta_info->ulRwSessionCount;
	ck_info->ulMaxPinLen = ta_info->ulMaxPinLen;
	ck_info->ulMinPinLen = ta_info->ulMinPinLen;
	ck_info->ulTotalPublicMemory = ta_info->ulTotalPublicMemory;
	ck_info->ulFreePublicMemory = ta_info->ulFreePublicMemory;
	ck_info->ulTotalPrivateMemory = ta_info->ulTotalPrivateMemory;
	ck_info->ulFreePrivateMemory = ta_info->ulFreePrivateMemory;
	MEMCPY_VERSION(ck_info, ta_info, hardwareVersion);
	MEMCPY_VERSION(ck_info, ta_info, firmwareVersion);
	MEMCPY_FIELD(ck_info, ta_info, utcTime);

	return CKR_OK;
}

/*
 * Helpers for CK/SKS conversions: tables of identifiers
 *
 * Define conversion tables between Cryptoki IDs and SKS 32bit IDs.
 * By convention, Cryptoki variable types CK_<XYZ> (i.e CK_ATTRIBUTE_TYPE)
 * are registered through DECLARE_CK2TA_FUNCTIONS(<xyz>); in ck_helpers.h
 * and locally through DEFINE_CK2TA_FUNCTIONS(<xyz>) in this source file.
 *
 * In the above description, <xyz> is the lower case equivalent of <XYZ>
 * in Cryptoki variable type definition label. I.e, for type CK_ATTRIBUTE_TYPE:
 *
 * In header file:
 *	DECLARE_CK2TA_FUNCTIONS(attribute_type);
 * In source file:
 *	static const struct ck2ta attribute_type[] = {
 *		CK2TA_ID_BRACE(CKA_CLASS, PKCS11_CKA_CLASS),
 *		CK2TA_ID_BRACE(CKA_TOKEN, PKCS11_CKA_TOKEN),
 *		...
 *	};
 *	DEFINE_CK2TA_FUNCTIONS(attribute_type, CK_ATTRIBUTE_TYPE)
 *
 * The above code snipet declares and defines functions ck2ta_attribute_type()
 * and ta2ck_attribute_type() using ID conversion array attribute type
 * defines in the source file. I.e.:
 *
 *	ta_id = ck2ta_attribute_type(attr->type);
 *	if (ta_id == PKCS11_UNDEFINED_ID)
 *		return CKR_ATTRIBUTE_TYPE_INVALID;
 *
 * Some Cryptoki variable types have mutliple ID enumerations that would
 * conflict if merged into a single ID valid list. For exmaple the flag type
 * CK_FLAGS is used by Cryptoki to enumerate mechanism flags, token flags and
 * more. This implementation defines specific tables per ID scope.
 * I.e:
 *	mechanism_flags for CKF_<FOO> related to mechanism flags.
 *	token_flags for  CKF_<FOO> related to token flags.
 */
struct ck2ta {
	CK_ULONG ck;
	uint32_t ta;
	// TODO: string for both IDs
};

/*
 * Macros to define the PKCS11 TA identifier relate to a Cryptoki identifier.
 * Use CK2TA_ID() when PKCS11 TA identifier label is PKCS11_<CK-label>.
 * Use CK2TA_BRACE() when specific PKCS11 TA identifier regarding Cryptoki CK label.
 */
#define CK2TA_ID(ck_id)			{ .ck = ck_id, .ta = PKCS11_ ## ck_id }
#define CK2TA_ID_BRACE(ck_id, ta_id)	{ .ck = ck_id, .ta = ta_id }

/* Flags: PKCS11 TA macro IDs use CKFx_ instead of CKF_, note the extra x */
#define CKFLAG2TA_ID(ta_ckfx, ck_id)	\
	{ .ck = CKF_ ## ck_id, .ta = PKCS11_ ## ta_ckfx ## ck_id }

#define TA2CK(out, in, conv)		ta2ck(out, in, conv, ARRAY_SIZE(conv))
#define CK2TA(out, in, conv)		ck2ta(out, in, conv, ARRAY_SIZE(conv))

#define DEFINE_CK2TA_FUNCTIONS(_conv_table, _ck_typeof)	\
	uint32_t ck2ta_ ## _conv_table(_ck_typeof ck)		\
	{							\
		uint32_t id = 0;					\
								\
		if (CK2TA(&id, ck, _conv_table))		\
			return PKCS11_UNDEFINED_ID;		\
								\
		return id;					\
	}							\
	CK_RV ta2ck_ ## _conv_table(_ck_typeof *ck, uint32_t ta) \
	{							\
		if (TA2CK(ck, ta, _conv_table))			\
			return CKR_GENERAL_ERROR;		\
								\
		return CKR_OK;					\
	}

static int ta2ck(CK_ULONG *out, uint32_t id,
		 const struct ck2ta *conv, size_t count)
{
	size_t n = 0;

	for (n = 0; n < count; n++) {
		if (id == conv[n].ta) {
			*out = conv[n].ck;
			return 0;
		}
	}

	return -1;
}

static int ck2ta(uint32_t *out, CK_ULONG id,
		 const struct ck2ta *conv, size_t count)
{
	size_t n = 0;

	for (n = 0; n < count; n++) {
		if (id == conv[n].ck) {
			*out = conv[n].ta;
			return 0;
		}
	}

	return -1;
}

/*
 * Identifiers conversion tables and related functions definitions.
 * Generic way goes:
 *
 * static const struct ck2ta <foo>[] = {
 *		CK2TA_ID_BRACE(CK[<X>]_<Y>),
 *		CK2TA_ID_BRACE(CK[<X>]_<Y>, PKCS11_<Z>),
 * };
 *
 * DEFINE_CK2TA_FUNCTIONS(<foo>, CK_<related-type-label>)
 */

static const struct ck2ta slot_flag[] = {
	CKFLAG2TA_ID(CKFS_, TOKEN_PRESENT),
	CKFLAG2TA_ID(CKFS_, REMOVABLE_DEVICE),
	CKFLAG2TA_ID(CKFS_, HW_SLOT),
};

DEFINE_CK2TA_FUNCTIONS(slot_flag, CK_FLAGS)

static const struct ck2ta token_flag[] = {
	CKFLAG2TA_ID(CKFT_, RNG),
	CKFLAG2TA_ID(CKFT_, WRITE_PROTECTED),
	CKFLAG2TA_ID(CKFT_, LOGIN_REQUIRED),
	CKFLAG2TA_ID(CKFT_, USER_PIN_INITIALIZED),
	CKFLAG2TA_ID(CKFT_, RESTORE_KEY_NOT_NEEDED),
	CKFLAG2TA_ID(CKFT_, CLOCK_ON_TOKEN),
	CKFLAG2TA_ID(CKFT_, PROTECTED_AUTHENTICATION_PATH),
	CKFLAG2TA_ID(CKFT_, DUAL_CRYPTO_OPERATIONS),
	CKFLAG2TA_ID(CKFT_, TOKEN_INITIALIZED),
	CKFLAG2TA_ID(CKFT_, USER_PIN_COUNT_LOW),
	CKFLAG2TA_ID(CKFT_, USER_PIN_FINAL_TRY),
	CKFLAG2TA_ID(CKFT_, USER_PIN_LOCKED),
	CKFLAG2TA_ID(CKFT_, USER_PIN_TO_BE_CHANGED),
	CKFLAG2TA_ID(CKFT_, SO_PIN_COUNT_LOW),
	CKFLAG2TA_ID(CKFT_, SO_PIN_FINAL_TRY),
	CKFLAG2TA_ID(CKFT_, SO_PIN_LOCKED),
	CKFLAG2TA_ID(CKFT_, SO_PIN_TO_BE_CHANGED),
	CKFLAG2TA_ID(CKFT_, ERROR_STATE),
};

DEFINE_CK2TA_FUNCTIONS(token_flag, CK_FLAGS)

static const struct ck2ta attribute_type[] = {
	CK2TA_ID(CKA_CLASS),
	CK2TA_ID(CKA_KEY_TYPE),
	CK2TA_ID(CKA_VALUE),
	CK2TA_ID(CKA_VALUE_LEN),
	CK2TA_ID(CKA_LABEL),
	CK2TA_ID(CKA_WRAP_TEMPLATE),
	CK2TA_ID(CKA_UNWRAP_TEMPLATE),
	CK2TA_ID(CKA_DERIVE_TEMPLATE),
	CK2TA_ID(CKA_START_DATE),
	CK2TA_ID(CKA_END_DATE),
	CK2TA_ID(CKA_OBJECT_ID),
	CK2TA_ID(CKA_APPLICATION),
	CK2TA_ID(CKA_MECHANISM_TYPE),
	CK2TA_ID(CKA_ID),
	CK2TA_ID(CKA_ALLOWED_MECHANISMS),
	CK2TA_ID(CKA_EC_PARAMS),
	CK2TA_ID(CKA_EC_POINT),
	CK2TA_ID(CKA_MODULUS),
	CK2TA_ID(CKA_MODULUS_BITS),
	CK2TA_ID(CKA_PUBLIC_EXPONENT),
	CK2TA_ID(CKA_PRIVATE_EXPONENT),
	CK2TA_ID(CKA_PRIME_1),
	CK2TA_ID(CKA_PRIME_2),
	CK2TA_ID(CKA_EXPONENT_1),
	CK2TA_ID(CKA_EXPONENT_2),
	CK2TA_ID(CKA_COEFFICIENT),
	CK2TA_ID(CKA_SUBJECT),
	CK2TA_ID(CKA_PUBLIC_KEY_INFO),
	/* Below are boolean attributes */
	CK2TA_ID(CKA_TOKEN),
	CK2TA_ID(CKA_PRIVATE),
	CK2TA_ID(CKA_TRUSTED),
	CK2TA_ID(CKA_SENSITIVE),
	CK2TA_ID(CKA_ENCRYPT),
	CK2TA_ID(CKA_DECRYPT),
	CK2TA_ID(CKA_WRAP),
	CK2TA_ID(CKA_UNWRAP),
	CK2TA_ID(CKA_SIGN),
	CK2TA_ID(CKA_SIGN_RECOVER),
	CK2TA_ID(CKA_VERIFY),
	CK2TA_ID(CKA_VERIFY_RECOVER),
	CK2TA_ID(CKA_DERIVE),
	CK2TA_ID(CKA_EXTRACTABLE),
	CK2TA_ID(CKA_LOCAL),
	CK2TA_ID(CKA_NEVER_EXTRACTABLE),
	CK2TA_ID(CKA_ALWAYS_SENSITIVE),
	CK2TA_ID(CKA_MODIFIABLE),
	CK2TA_ID(CKA_COPYABLE),
	CK2TA_ID(CKA_DESTROYABLE),
	CK2TA_ID(CKA_ALWAYS_AUTHENTICATE),
	CK2TA_ID(CKA_WRAP_WITH_TRUSTED),
	/* Specifc PKCS11 TA attribute IDs */
	CK2TA_ID_BRACE(CKA_VENDOR_EC_POINT_X, PKCS11_CKA_EC_POINT_X),
	CK2TA_ID_BRACE(CKA_VENDOR_EC_POINT_Y, PKCS11_CKA_EC_POINT_Y),
	CK2TA_ID_BRACE(CK_VENDOR_INVALID_ID, PKCS11_UNDEFINED_ID),
};

DEFINE_CK2TA_FUNCTIONS(attribute_type, CK_ATTRIBUTE_TYPE)

static const struct ck2ta mechanism_type[] = {
	CK2TA_ID(CKM_MD5),
	CK2TA_ID(CKM_SHA_1),
	CK2TA_ID(CKM_SHA224),
	CK2TA_ID(CKM_SHA256),
	CK2TA_ID(CKM_SHA384),
	CK2TA_ID(CKM_SHA512),

	CK2TA_ID(CKM_AES_ECB),
	CK2TA_ID(CKM_AES_CBC),
	CK2TA_ID(CKM_AES_CBC_PAD),
	CK2TA_ID(CKM_AES_CTR),
	CK2TA_ID(CKM_AES_GCM),
	CK2TA_ID(CKM_AES_CCM),
	CK2TA_ID(CKM_AES_CTS),
	CK2TA_ID(CKM_AES_GMAC),
	CK2TA_ID(CKM_AES_CMAC),
	CK2TA_ID(CKM_AES_CMAC_GENERAL),
	CK2TA_ID(CKM_AES_ECB_ENCRYPT_DATA),
	CK2TA_ID(CKM_AES_CBC_ENCRYPT_DATA),
	CK2TA_ID(CKM_AES_KEY_GEN),
	CK2TA_ID(CKM_AES_XCBC_MAC),

	CK2TA_ID(CKM_GENERIC_SECRET_KEY_GEN),

	CK2TA_ID(CKM_MD5_HMAC),
	CK2TA_ID(CKM_SHA_1_HMAC),
	CK2TA_ID(CKM_SHA224_HMAC),
	CK2TA_ID(CKM_SHA256_HMAC),
	CK2TA_ID(CKM_SHA384_HMAC),
	CK2TA_ID(CKM_SHA512_HMAC),

	CK2TA_ID(CKM_EC_KEY_PAIR_GEN),
	CK2TA_ID(CKM_ECDSA),
	CK2TA_ID(CKM_ECDSA_SHA1),
	CK2TA_ID(CKM_ECDSA_SHA224),
	CK2TA_ID(CKM_ECDSA_SHA256),
	CK2TA_ID(CKM_ECDSA_SHA384),
	CK2TA_ID(CKM_ECDSA_SHA512),
	CK2TA_ID(CKM_ECDH1_DERIVE),
	CK2TA_ID(CKM_ECDH1_COFACTOR_DERIVE),
	CK2TA_ID(CKM_ECMQV_DERIVE),
	CK2TA_ID(CKM_ECDH_AES_KEY_WRAP),

	CK2TA_ID(CKM_RSA_PKCS_KEY_PAIR_GEN),
	CK2TA_ID(CKM_RSA_PKCS),
	CK2TA_ID(CKM_RSA_9796),
	CK2TA_ID(CKM_RSA_X_509),
	CK2TA_ID(CKM_SHA1_RSA_PKCS),
	CK2TA_ID(CKM_RSA_PKCS_OAEP),
	CK2TA_ID(CKM_RSA_PKCS_PSS),
	CK2TA_ID(CKM_SHA1_RSA_PKCS_PSS),
	CK2TA_ID(CKM_SHA256_RSA_PKCS),
	CK2TA_ID(CKM_SHA384_RSA_PKCS),
	CK2TA_ID(CKM_SHA512_RSA_PKCS),
	CK2TA_ID(CKM_SHA256_RSA_PKCS_PSS),
	CK2TA_ID(CKM_SHA384_RSA_PKCS_PSS),
	CK2TA_ID(CKM_SHA512_RSA_PKCS_PSS),
	CK2TA_ID(CKM_SHA224_RSA_PKCS),
	CK2TA_ID(CKM_SHA224_RSA_PKCS_PSS),
	CK2TA_ID(CKM_RSA_AES_KEY_WRAP),

	CK2TA_ID_BRACE(CK_VENDOR_INVALID_ID, PKCS11_UNDEFINED_ID),
};

DEFINE_CK2TA_FUNCTIONS(mechanism_type, CK_MECHANISM_TYPE)

static const struct ck2ta mechanism_flag[] = {
	CKFLAG2TA_ID(CKFM_, HW),
	CKFLAG2TA_ID(CKFM_, ENCRYPT),
	CKFLAG2TA_ID(CKFM_, DECRYPT),
	CKFLAG2TA_ID(CKFM_, DIGEST),
	CKFLAG2TA_ID(CKFM_, SIGN),
	CKFLAG2TA_ID(CKFM_, SIGN_RECOVER),
	CKFLAG2TA_ID(CKFM_, VERIFY),
	CKFLAG2TA_ID(CKFM_, VERIFY_RECOVER),
	CKFLAG2TA_ID(CKFM_, GENERATE),
	CKFLAG2TA_ID(CKFM_, GENERATE_KEY_PAIR),
	CKFLAG2TA_ID(CKFM_, WRAP),
	CKFLAG2TA_ID(CKFM_, UNWRAP),
	CKFLAG2TA_ID(CKFM_, DERIVE),
	CKFLAG2TA_ID(CKFM_, EC_F_P),
	CKFLAG2TA_ID(CKFM_, EC_F_2M),
	CKFLAG2TA_ID(CKFM_, EC_ECPARAMETERS),
	CKFLAG2TA_ID(CKFM_, EC_NAMEDCURVE),
	CKFLAG2TA_ID(CKFM_, EC_UNCOMPRESS),
	CKFLAG2TA_ID(CKFM_, EC_COMPRESS),
};

DEFINE_CK2TA_FUNCTIONS(mechanism_flag, CK_FLAGS)

static const struct ck2ta object_class[] = {
	CK2TA_ID(CKO_SECRET_KEY),
	CK2TA_ID(CKO_PUBLIC_KEY),
	CK2TA_ID(CKO_PRIVATE_KEY),
	CK2TA_ID(CKO_OTP_KEY),
	CK2TA_ID(CKO_CERTIFICATE),
	CK2TA_ID(CKO_DATA),
	CK2TA_ID(CKO_DOMAIN_PARAMETERS),
	CK2TA_ID(CKO_HW_FEATURE),
	CK2TA_ID(CKO_MECHANISM),
	CK2TA_ID_BRACE(CK_VENDOR_INVALID_ID, PKCS11_UNDEFINED_ID),
};

DEFINE_CK2TA_FUNCTIONS(object_class, CK_OBJECT_CLASS)

static const struct ck2ta key_type[] = {
	CK2TA_ID(CKK_AES),
	CK2TA_ID(CKK_GENERIC_SECRET),
	CK2TA_ID(CKK_MD5_HMAC),
	CK2TA_ID(CKK_SHA_1_HMAC),
	CK2TA_ID(CKK_SHA224_HMAC),
	CK2TA_ID(CKK_SHA256_HMAC),
	CK2TA_ID(CKK_SHA384_HMAC),
	CK2TA_ID(CKK_SHA512_HMAC),
	CK2TA_ID(CKK_RSA),
	CK2TA_ID(CKK_EC),
	CK2TA_ID(CKK_DSA),
	CK2TA_ID(CKK_DH),
	CK2TA_ID_BRACE(CK_VENDOR_INVALID_ID, PKCS11_UNDEFINED_ID),
};

DEFINE_CK2TA_FUNCTIONS(key_type, CK_KEY_TYPE)

static const struct ck2ta ec_kdf_type[] = {
	CK2TA_ID(CKD_NULL),
	CK2TA_ID(CKD_SHA1_KDF),
	CK2TA_ID(CKD_SHA1_KDF_ASN1),
	CK2TA_ID(CKD_SHA1_KDF_CONCATENATE),
	CK2TA_ID(CKD_SHA224_KDF),
	CK2TA_ID(CKD_SHA256_KDF),
	CK2TA_ID(CKD_SHA384_KDF),
	CK2TA_ID(CKD_SHA512_KDF),
	CK2TA_ID(CKD_CPDIVERSIFY_KDF),
};

DEFINE_CK2TA_FUNCTIONS(ec_kdf_type, CK_EC_KDF_TYPE)

static const struct ck2ta rsa_pkcs_mgf_type[] = {
	CK2TA_ID(CKG_MGF1_SHA1),
	CK2TA_ID(CKG_MGF1_SHA224),
	CK2TA_ID(CKG_MGF1_SHA256),
	CK2TA_ID(CKG_MGF1_SHA384),
	CK2TA_ID(CKG_MGF1_SHA512),
};

DEFINE_CK2TA_FUNCTIONS(rsa_pkcs_mgf_type, CK_RSA_PKCS_MGF_TYPE)

static const struct ck2ta rsa_pkcs_oaep_source_type[] = {
	CK2TA_ID(CKZ_DATA_SPECIFIED),
};

DEFINE_CK2TA_FUNCTIONS(rsa_pkcs_oaep_source_type, CK_RSA_PKCS_OAEP_SOURCE_TYPE)

static const struct ck2ta user_type[] = {
	CK2TA_ID(CKU_SO),
	CK2TA_ID(CKU_USER),
	CK2TA_ID(CKU_CONTEXT_SPECIFIC),
};

DEFINE_CK2TA_FUNCTIONS(user_type, CK_USER_TYPE)

static const struct ck2ta error_code[] = {
	CK2TA_ID(CKR_OK),
	CK2TA_ID(CKR_GENERAL_ERROR),
	CK2TA_ID(CKR_DEVICE_MEMORY),
	CK2TA_ID(CKR_ARGUMENTS_BAD),
	CK2TA_ID(CKR_BUFFER_TOO_SMALL),
	CK2TA_ID(CKR_FUNCTION_FAILED),
	CK2TA_ID(CKR_ATTRIBUTE_TYPE_INVALID),
	CK2TA_ID(CKR_ATTRIBUTE_VALUE_INVALID),
	CK2TA_ID(CKR_OBJECT_HANDLE_INVALID),
	CK2TA_ID(CKR_KEY_HANDLE_INVALID),
	CK2TA_ID(CKR_MECHANISM_INVALID),
	CK2TA_ID(CKR_SLOT_ID_INVALID),
	CK2TA_ID(CKR_SESSION_HANDLE_INVALID),
	CK2TA_ID(CKR_PIN_INCORRECT),
	CK2TA_ID(CKR_PIN_LOCKED),
	CK2TA_ID(CKR_PIN_EXPIRED),
	CK2TA_ID(CKR_PIN_INVALID),
	CK2TA_ID(CKR_OPERATION_ACTIVE),
	CK2TA_ID(CKR_KEY_FUNCTION_NOT_PERMITTED),
	CK2TA_ID(CKR_OPERATION_NOT_INITIALIZED),
	CK2TA_ID(CKR_SESSION_READ_ONLY),
	CK2TA_ID(CKR_MECHANISM_PARAM_INVALID),
	CK2TA_ID(CKR_TOKEN_WRITE_PROTECTED),
	CK2TA_ID(CKR_TOKEN_NOT_PRESENT),
	CK2TA_ID(CKR_TOKEN_NOT_RECOGNIZED),
	CK2TA_ID(CKR_ACTION_PROHIBITED),
	CK2TA_ID(CKR_ATTRIBUTE_READ_ONLY),
	CK2TA_ID(CKR_PIN_TOO_WEAK),
	CK2TA_ID(CKR_CURVE_NOT_SUPPORTED),
	CK2TA_ID(CKR_DOMAIN_PARAMS_INVALID),
	CK2TA_ID(CKR_USER_ALREADY_LOGGED_IN),
	CK2TA_ID(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
	CK2TA_ID(CKR_USER_NOT_LOGGED_IN),
	CK2TA_ID(CKR_USER_PIN_NOT_INITIALIZED),
	CK2TA_ID(CKR_USER_TOO_MANY_TYPES),
	CK2TA_ID(CKR_USER_TYPE_INVALID),
	CK2TA_ID(CKR_SESSION_READ_ONLY_EXISTS),
	CK2TA_ID(CKR_TEMPLATE_INCONSISTENT),
	CK2TA_ID_BRACE(CK_VENDOR_INVALID_ID, PKCS11_UNDEFINED_ID),
};

CK_RV ta2ck_rv(uint32_t ta)
{
	CK_ULONG rv;

	if (TA2CK(&rv, ta, error_code))
		return CKR_GENERAL_ERROR;

	return (CK_RV)rv;
}

CK_RV teec2ck_rv(TEEC_Result res)
{
	switch (res) {
	case TEEC_SUCCESS:
		return CKR_OK;
	case TEEC_ERROR_OUT_OF_MEMORY:
		return CKR_DEVICE_MEMORY;
	case TEEC_ERROR_BAD_PARAMETERS:
		return CKR_ARGUMENTS_BAD;
	case TEEC_ERROR_SHORT_BUFFER:
		return CKR_BUFFER_TOO_SMALL;
	default:
		return CKR_FUNCTION_FAILED;
	}
}
/* Convert a array of mechanism type from PKCS11 TA IDs into CK_MECHANIMS_TYPE */
CK_RV ta2ck_mechanism_type_list(CK_MECHANISM_TYPE *dst,
				 void *src, size_t count)
{
	CK_MECHANISM_TYPE *ck = dst;
	char *ta_src = src;
	size_t n = 0;
	uint32_t proc = 0;

	for (n = 0; n < count; n++, ta_src += sizeof(uint32_t), ck++) {
		memcpy(&proc, ta_src, sizeof(proc));
		if (ta2ck_mechanism_type(ck, proc))
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}

/* Convert structure CK_MECHANIMS_INFO from PKCS11 to CK IDs (3 ulong fields) */
CK_RV ta2ck_mechanism_info(CK_MECHANISM_INFO *info, void *src)
{
	struct pkcs11_mechanism_info ta_info;
	CK_FLAGS ck_flag = 0;
	uint32_t mask = 0;
	CK_RV rv = 0;

	memcpy(&ta_info, src, sizeof(ta_info));

	info->ulMinKeySize = ta_info.min_key_size;
	info->ulMaxKeySize = ta_info.max_key_size;

	info->flags = 0;
	for (mask = 1; mask; mask <<= 1) {
		if (!(ta_info.flags & mask))
			continue;

		rv = ta2ck_mechanism_flag(&ck_flag, mask);
		if (rv)
			return rv;

		info->flags |= ck_flag;
	}

	return CKR_OK;
}

/*
 * Helper functions to analyse CK fields
 */
size_t ck_attr_is_class(uint32_t id)
{
	if (id == CKA_CLASS)
		return sizeof(CK_ULONG);
	else
		return 0;
}

size_t ck_attr_is_type(uint32_t id)
{
	switch (id) {
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_TYPE:
	case CKA_HW_FEATURE_TYPE:
	case CKA_MECHANISM_TYPE:
		return sizeof(CK_ULONG);
	default:
		return 0;
	}
}
int sks_object_has_boolprop(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_DATA:
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_DOMAIN_PARAMETERS:
		return 1;
	default:
		return 0;
	}
}
int sks_class_has_type(uint32_t class)
{
	switch (class) {
	case PKCS11_CKO_CERTIFICATE:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_MECHANISM:
	case PKCS11_CKO_HW_FEATURE:
		return 1;
	default:
		return 0;
	}
}

uint32_t ck2ta_type_in_class(CK_ULONG ck, CK_ULONG class)
{
	switch (class) {
	case CKO_DATA:
		return 0;
	case CKO_SECRET_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_OTP_KEY:
		return ck2ta_key_type(ck);
	case CKO_MECHANISM:
		return ck2ta_mechanism_type(ck);
	case CKO_CERTIFICATE:
	default:
		return PKCS11_UNDEFINED_ID;
	}
}

CK_RV ta2ck_type_in_class(CK_ULONG *ck, uint32_t ta_id, CK_ULONG class)
{
	switch (class) {
	case PKCS11_CKO_DATA:
		return CKR_NO_EVENT;
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_OTP_KEY:
		return ta2ck_key_type(ck, ta_id);
	case PKCS11_CKO_MECHANISM:
		return ta2ck_mechanism_type(ck, ta_id);
	case PKCS11_CKO_CERTIFICATE:
	default:
		return CKR_GENERAL_ERROR;
	}
}

CK_RV ck_guess_key_type(CK_MECHANISM_PTR mecha,
			CK_ATTRIBUTE_PTR attrs, CK_ULONG_PTR count,
			CK_ATTRIBUTE_PTR *attrs_new_p)
{
	size_t n;
	CK_ULONG count_new = *count;
	CK_ATTRIBUTE_PTR attrs_new = NULL;
	CK_KEY_TYPE_PTR key_type_p = NULL;
	int key_type_present = 0;
	CK_RV rv;

	for (n = 0; n < *count; n++) {
		if (attrs[n].type == CKA_KEY_TYPE) {
			key_type_present = 1;
			break;
		}
	}
	if (!key_type_present)
		count_new++;

	attrs_new = malloc(count_new * sizeof(CK_ATTRIBUTE));
	if (attrs_new == NULL)
		return CKR_HOST_MEMORY;

	memcpy(attrs_new, attrs, (*count) * sizeof(CK_ATTRIBUTE));

	if (key_type_present) {
		rv = CKR_OK;
		goto bail;
	}

	key_type_p = malloc(sizeof(CK_KEY_TYPE));
	if (key_type_p == NULL) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	switch (mecha->mechanism) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		*key_type_p = CKK_RSA;
		attrs_new[count_new - 1].type = CKA_KEY_TYPE;
		attrs_new[count_new - 1].pValue = key_type_p;
		attrs_new[count_new - 1].ulValueLen = sizeof(CK_KEY_TYPE);
		rv = CKR_OK;
		break;
	case CKM_EC_KEY_PAIR_GEN:
		*key_type_p = CKK_EC;
		attrs_new[count_new - 1].type = CKA_KEY_TYPE;
		attrs_new[count_new - 1].pValue = key_type_p;
		attrs_new[count_new - 1].ulValueLen = sizeof(CK_KEY_TYPE);
		rv = CKR_OK;
		break;
	default:
		rv = CKR_TEMPLATE_INCOMPLETE;
		break;
	}

bail:
	if (rv == CKR_OK) {
		*attrs_new_p = attrs_new;
		*count = count_new;
	} else {
		if (attrs_new)
			free(attrs_new);
		if (key_type_p)
			free(key_type_p);
	}

	return rv;
}
