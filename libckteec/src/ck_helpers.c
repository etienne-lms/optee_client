// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <ck_debug.h>
#include <pkcs11_ta.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>

#include "ck_helpers.h"
#include "local_utils.h"

#ifdef DEBUG
void ckteec_assert_expected_rv(const char *function, CK_RV rv,
			       const CK_RV *expected_rv, size_t expected_count)
{
	size_t n = 0;

	for (n = 0; n < expected_count; n++)
		if (rv == expected_rv[n])
			return;

	fprintf(stderr, "libckteec: %s: unexpected return value 0x%lx (%s)\n",
		function, rv, ckr2str(rv));

	assert(0);
}
#endif

/*
 * Helpers for conversion of CK IDs to/from PKCS11 TA IDs: tables of identifiers
 *
 * Define conversion tables between Cryptoki IDs and PKCS11 TA 32bit IDs.
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
	uint32_t mecha_id = 0;

	for (n = 0; n < count; n++, ta_src += sizeof(mecha_id), ck++) {
		memcpy(&mecha_id, ta_src, sizeof(mecha_id));
		dst[n] = mecha_id;
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

int ta_object_has_boolprop(uint32_t class)
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

int ta_class_has_type(uint32_t class)
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
		return ck;
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
		*ck = ta_id;
		return CKR_OK;
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
