/*
 * Copyright (c) 2017-2018, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ck_debug.h>
#include <pkcs11_ta.h>

#include "ck_helpers.h"
#include "local_utils.h"
#include "serializer.h"
#include "serialize_ck.h"

/*
 * Generic way of serializing CK keys, certif, mechanism parameters, ...
 * In cryptoki 2.40 parameters are almost all packaged as struture below:
 */
struct ck_ref {
	CK_ULONG id;
	CK_BYTE_PTR ptr;
	CK_ULONG len;
};

#if 0
/*
 * Append cryptoki generic buffer reference structure into a serial
 * object for sharing with the PKCS11 TA.
 *
 * ck_ref points to a structure aligned CK reference (attributes or else)
 */
static CK_RV serialize_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, ref->len);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, ref->ptr, ref->len);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}

/*
 * ck_ref points to a structure aligned CK reference (attributes or else)
 *
 * Same as serialize_ck_ref but reference is a ULONG so the blob size
 * to be set accoring to the 32bit/64bit configuration of target CK ABI.
 */
static CK_RV serialize_ulong_ck_ref(struct serializer *obj, void *ck_ref)
{
	struct ck_ref *ref = ck_ref;
	CK_ULONG ck_value;
	uint32_t pkcs11_value;
	CK_RV rv;

	rv = serialize_ck_ulong(obj, ref->id);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, sizeof(pkcs11_value));
	if (rv)
		return rv;

	memcpy(&ck_value, ref->ptr, sizeof(CK_ULONG));
	pkcs11_value = ck_value;

	rv = serialize_buffer(obj, &pkcs11_value, sizeof(pkcs11_value));
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}
#endif

/*
 * This is for attributes that contains data memory indirections.
 * In other words, an attributes that defines a list of attributes.
 * They are identified from the attribute type CKA_...
 *
 * @obj - ref used to track the serial object being created
 * @attribute - pointer to a structure aligned of the CK_ATTRIBUTE struct
 */
static CK_RV serialize_indirect_attribute(struct serializer *obj,
					  CK_ATTRIBUTE_PTR attribute)
{
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG count;
	CK_RV rv;
	struct serializer obj2;

	switch (attribute->type) {
	/* These are serialized each seperately */
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		count = attribute->ulValueLen / sizeof(CK_ATTRIBUTE);
		attr = (CK_ATTRIBUTE_PTR)attribute->pValue;
		break;
	default:
		return CKR_NO_EVENT;
	}

	/* Create a serialized object for the content */
	rv = serialize_ck_attributes(&obj2, attr, count);
	if (rv)
		return rv;

	/*
	 * Append the created serialized object into target object:
	 * [attrib-id][byte-size][attributes-data]
	 */
	rv = serialize_32b(obj, ck2ta_attribute_type(attribute->type));
	if (rv)
		return rv;

	rv = serialize_32b(obj, obj2.size);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, obj2.buffer, obj2.size);
	if (rv)
		return rv;

	obj->item_count++;

	return rv;
}

static CK_RV deserialize_indirect_attribute(struct pkcs11_attribute_head *obj,
					    CK_ATTRIBUTE_PTR attribute)
{
	CK_ULONG count;
	CK_ATTRIBUTE_PTR attr;
	CK_RV rv;

	switch (attribute->type) {
	/* These are serialized each seperately */
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		count = attribute->ulValueLen / sizeof(CK_ATTRIBUTE);
		attr = (CK_ATTRIBUTE_PTR)attribute->pValue;
		break;
	default:
		return CKR_GENERAL_ERROR;
	}

	/*
	 * deserialize_ck_attributes expects pkcs11_attribute_head,
	 * not pkcs11_object_head, so we need to correct the pointer
	 */
	rv = deserialize_ck_attributes(obj->data, attr, count);
	return rv;
}

static int ck_attr_is_ulong(CK_ATTRIBUTE_TYPE attribute_id)
{
	if (ck_attr_is_class(attribute_id) || ck_attr_is_type(attribute_id))
		return true;

	switch (attribute_id) {
	case CKA_VALUE_LEN:
	case CKA_MODULUS_BITS:
		return true;
	default:
		return false;
	}
}

static CK_RV serialize_ck_attribute(struct serializer *obj, CK_ATTRIBUTE *attr)
{
	uint32_t pkcs11_id = PKCS11_UNDEFINED_ID;
	uint32_t pkcs11_size = 0;
	uint32_t pkcs11_data32;
	void *pkcs11_pdata;
	int pkcs11_pdata_alloced = 0;
	CK_ULONG ck_ulong = 0;		/* keep compiler happy */
	CK_RV rv;
	unsigned int n;
	unsigned int m;

	/* Expect only those from the identification table */
	pkcs11_id = ck2ta_attribute_type(attr->type);
	if (pkcs11_id == PKCS11_UNDEFINED_ID)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	if (ck_attr_is_ulong(attr->type)) {
		/* PKCS#11 CK_ULONG are use */
		if (attr->ulValueLen != sizeof(CK_ULONG))
			return CKR_ATTRIBUTE_TYPE_INVALID;

		memcpy(&ck_ulong, attr->pValue, sizeof(ck_ulong));
	}

	switch (attr->type) {
	case CKA_CLASS:
		pkcs11_data32 = ck2ta_object_class(ck_ulong);
		pkcs11_pdata = &pkcs11_data32;
		pkcs11_size = sizeof(uint32_t);
		break;

	case CKA_KEY_TYPE:
		pkcs11_data32 = ck2ta_key_type(ck_ulong);
		pkcs11_pdata = &pkcs11_data32;
		pkcs11_size = sizeof(uint32_t);
		break;

	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		return serialize_indirect_attribute(obj, attr);

	case CKA_ALLOWED_MECHANISMS:
		n = attr->ulValueLen / sizeof(CK_ULONG);
		pkcs11_size = n * sizeof(uint32_t);
		pkcs11_pdata = malloc(pkcs11_size);
		if (!pkcs11_pdata)
			return CKR_HOST_MEMORY;

		pkcs11_pdata_alloced = 1;

		for (m = 0; m < n; m++) {
			CK_MECHANISM_TYPE *type = attr->pValue;

			pkcs11_data32 = ck2ta_mechanism_type(type[m]);
			if (pkcs11_data32 == PKCS11_UNDEFINED_ID) {
				free(pkcs11_pdata);
				return CKR_MECHANISM_INVALID;
			}

			((uint32_t *)pkcs11_pdata)[m] = pkcs11_data32;
		}
		break;

	/* Attributes which data value do not need conversion (aside ulong) */
	default:
		if (ck_attr_is_ulong(attr->type)) {
			pkcs11_data32 = (uint32_t)ck_ulong;
			pkcs11_pdata = &pkcs11_data32;
			pkcs11_size = sizeof(uint32_t);
		} else {
			pkcs11_pdata = attr->pValue;
			pkcs11_size = attr->ulValueLen;
		}
		break;
	}

	rv = serialize_32b(obj, pkcs11_id);
	if (rv)
		goto bail;

	rv = serialize_32b(obj, pkcs11_size);
	if (rv)
		goto bail;

	rv = serialize_buffer(obj, pkcs11_pdata, pkcs11_size);
	if (rv)
		goto bail;

	obj->item_count++;

bail:
	if (pkcs11_pdata_alloced)
		free(pkcs11_pdata);

	return rv;
}

#ifdef PKCS11_WITH_GENERIC_ATTRIBS_IN_HEAD
static CK_RV get_class(struct serializer *obj, struct ck_ref *ref)
{
	CK_ULONG ck_value;
	uint32_t pkcs11_value;

	if (ref->len != sizeof(ck_value))
		return CKR_TEMPLATE_INCONSISTENT;

	memcpy(&ck_value, ref->ptr, sizeof(ck_value));

	pkcs11_value = ck2ta_object_class(ck_value);

	if (pkcs11_value == PKCS11_UNDEFINED_ID)
		return CKR_TEMPLATE_INCONSISTENT; // TODO: errno

	if (obj->object == PKCS11_UNDEFINED_ID)
		obj->object = pkcs11_value;

	if (obj->object != pkcs11_value) {
		printf("Attribute %s redefined\n", cka2str(ref->id));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

static CK_RV get_type(struct serializer *obj, struct ck_ref *ref,
		      CK_ULONG class)
{
	CK_ULONG ck_value;
	uint32_t pkcs11_value;

	if (ref->len != sizeof(ck_value))
		return CKR_TEMPLATE_INCONSISTENT;

	memcpy(&ck_value, ref->ptr, sizeof(ck_value));

	pkcs11_value = ck2ta_type_in_class(ck_value, class);

	if (pkcs11_value == PKCS11_UNDEFINED_ID)
		return CKR_TEMPLATE_INCONSISTENT; // TODO: errno

	if (obj->type == PKCS11_UNDEFINED_ID)
		obj->type = pkcs11_value;

	if (obj->type != pkcs11_value) {
		printf("Attribute %s redefined\n",
			cktype2str(ck_value, class));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

#ifdef /* PKCS11_WITH_BOOLPROP_ATTRIBS_IN_HEAD */
static CK_RV get_boolprop(struct serializer *obj,
			  struct ck_ref *ref, uint32_t *sanity)
{
	int shift;
	uint32_t mask;
	uint32_t value;
	uint32_t *boolprop_ptr;
	uint32_t *sanity_ptr;
	CK_BBOOL bbool;

	/* Get the boolean property shift position and value */
	shift = ck_attr2boolprop_shift(ref->id);
	if (shift < 0)
		return CKR_NO_EVENT;

	if (shift >= PKCS11_MAX_BOOLPROP_SHIFT)
		return CKR_FUNCTION_FAILED;

	memcpy(&bbool, ref->ptr, sizeof(bbool));

	mask = 1 << (shift % 32);
	if (bbool == CK_TRUE)
		value = mask;
	else
		value = 0;

	/* Locate the current config value for the boolean property */
	boolprop_ptr = obj->boolprop + (shift / 32);
	sanity_ptr = sanity + (shift / 32);

	/* Error if already set to a different boolean value */
	if ((*sanity_ptr & mask) && value != (*boolprop_ptr & mask)) {
		printf("Attribute %s redefined\n", cka2str(ref->id));
		return CKR_TEMPLATE_INCONSISTENT;
	}

	*sanity_ptr |= mask;
	if (value)
		*boolprop_ptr |= mask;
	else
		*boolprop_ptr &= ~mask;

	return CKR_OK;
}
#endif /* PKCS11_WITH_BOOLPROP_ATTRIBS_IN_HEAD */

/*
 * Extract object generic attributes
 * - all objects must provide at least a class
 * - some classes expect a type
 * - some classes can define generic boolean attributes (boolprops)
 */
static CK_RV serialize_generic_attributes(struct serializer *obj,
					  CK_ATTRIBUTE_PTR attributes,
					  CK_ULONG count)
{
	struct ck_ref *ref;
	size_t n;
	uint32_t sanity[PKCS11_MAX_BOOLPROP_ARRAY] = { 0 };
	CK_RV rv = CKR_OK;
	CK_ULONG class;

	for (ref = (struct ck_ref *)attributes, n = 0; n < count; n++, ref++) {
		if (ck_attr_is_class(ref->id))
			rv = get_class(obj, ref);
		if (rv)
			return rv;
	}

	rv = ta2ck_object_class(&class, obj->object);
	if (rv)
		return rv;

	for (ref = (struct ck_ref *)attributes, n = 0; n < count; n++, ref++) {
		if (ck_attr_is_type(ref->id)) {
			rv = get_type(obj, ref, class);
			if (rv)
				return rv;

			continue;
		}

#ifdef PKCS11_WITH_BOOLPROP_ATTRIBS_IN_HEAD
		if (ta_object_has_boolprop(obj->object) &&
		    ck_attr2boolprop_shift(ref->id) >= 0) {
			rv = get_boolprop(obj, ref, sanity);
			if (rv == CKR_NO_EVENT)
				rv = CKR_OK;

			if (rv)
				return rv;

			continue;
		}
#endif
	}

	return rv;
}

static int ck_attr_is_generic(CK_ULONG attribute_id)
{
	return (ck_attr_is_class(attribute_id) ||
#ifdef PKCS11_WITH_BOOLPROP_ATTRIBS_IN_HEAD
		(ck_attr2boolprop_shift(attribute_id) >= 0) ||
#endif
		ck_attr_is_type(attribute_id));
}
#endif /* PKCS11_WITH_GENERIC_ATTRIBS_IN_HEAD */

/* CK attribute reference arguments are list of attribute item */
CK_RV serialize_ck_attributes(struct serializer *obj,
				CK_ATTRIBUTE_PTR attributes, CK_ULONG count)
{
	CK_ATTRIBUTE_PTR cur_attr = attributes;
	CK_ULONG n = count;
	CK_RV rv = CKR_OK;

	rv = init_serial_object(obj);
	if (rv)
		return rv;

#ifdef PKCS11_WITH_GENERIC_ATTRIBS_IN_HEAD
	rv = serialize_generic_attributes(obj, attributes, count);
	if (rv)
		goto out;
#endif

	for (; n; n--, cur_attr++) {
		CK_ATTRIBUTE attr;

		memcpy(&attr, cur_attr, sizeof(attr));

#ifdef PKCS11_WITH_GENERIC_ATTRIBS_IN_HEAD
		if (ck_attr_is_generic(attr.type))
			continue;
#endif

		rv = serialize_ck_attribute(obj, &attr);
		if (rv)
			goto out;
	}

out:
	if (rv)
		release_serial_object(obj);
	else
		finalize_serial_object(obj);

	return rv;
}

static CK_RV deserialize_ck_attribute(struct pkcs11_attribute_head *in,
				      CK_ATTRIBUTE_PTR out)
{
	CK_ULONG ck_ulong;
	uint32_t pkcs11_data32 = 0;
	size_t n;
	CK_RV rv;

	rv = ta2ck_attribute_type(&(out->type), in->id);
	if (rv)
		return rv;

	if (out->ulValueLen < in->size) {
		out->ulValueLen = in->size;
		return CKR_OK;
	}
	out->ulValueLen = in->size;

	if (!out->pValue)
		return CKR_OK;

	/* Specific ulong encoded as 32bit in PKCS11 TA API */
	if (ck_attr_is_ulong(out->type)) {
		if (out->ulValueLen != sizeof(CK_ULONG))
			return CKR_ATTRIBUTE_TYPE_INVALID;

		memcpy(&pkcs11_data32, in->data, sizeof(uint32_t));
	}

	switch (out->type) {
	case CKA_CLASS:
		rv = ta2ck_object_class(&ck_ulong, pkcs11_data32);
		if (rv)
			return rv;
		memcpy(out->pValue, &ck_ulong, sizeof(CK_ULONG));
		break;

	case CKA_KEY_TYPE:
		rv = ta2ck_key_type(&ck_ulong, pkcs11_data32);
		if (rv)
			return rv;
		memcpy(out->pValue, &ck_ulong, sizeof(CK_ULONG));
		break;

	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
		rv = deserialize_indirect_attribute(in, out->pValue);
		break;

	case CKA_ALLOWED_MECHANISMS:
		n = out->ulValueLen / sizeof(CK_ULONG);
		rv = ta2ck_mechanism_type_list(out->pValue, in->data, n);
		break;

	/* Attributes which data value do not need conversion (aside ulong) */
	default:
		memcpy(out->pValue, in->data, out->ulValueLen);
		rv = CKR_OK;
		break;
	}

	return rv;
}

CK_RV deserialize_ck_attributes(uint8_t *in, CK_ATTRIBUTE_PTR attributes,
				CK_ULONG count)
{
	CK_ATTRIBUTE_PTR cur_attr = attributes;
	CK_ULONG n;
	CK_RV rv = CKR_OK;
	uint8_t *curr_head = in;
	size_t len;

	curr_head += sizeof(struct pkcs11_object_head);

#ifdef PKCS11_WITH_GENERIC_ATTRIBS_IN_HEAD
#error Not supported.
#endif

	for (n = count; n > 0; n--, cur_attr++, curr_head += len) {
		struct pkcs11_attribute_head *cli_ref =
			(struct pkcs11_attribute_head *)(void *)curr_head;

		len = sizeof(*cli_ref);
		/*
		 * Can't trust size becuase it was set to reflect
		 * required buffer.
		 */
		if (cur_attr->pValue)
			len += cli_ref->size;

		rv = deserialize_ck_attribute(cli_ref, cur_attr);
		if (rv)
			goto out;
	}

out:
	return rv;
}

/*
 * Serialization of CK mechanism parameters
 *
 * Most mechanism have no parameters.
 * Some mechanism have a single 32bit parameter.
 * Some mechanism have a specific parameter structure which may contain
 * indirected data (data referred by a buffer pointer).
 *
 * Below are each structure specific mechanisms parameters.
 *
 * Be careful that CK_ULONG based types translate to 32bit ulong fields in
 * the PKCS11 ABI.
 */

/*
 * typedef struct CK_AES_CTR_PARAMS {
 *	CK_ULONG ulCounterBits;
 *	CK_BYTE cb[16];
 * } CK_AES_CTR_PARAMS;
 */
static CK_RV serialize_mecha_aes_ctr(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_AES_CTR_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;
	uint32_t size;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	size = sizeof(uint32_t) + sizeof(param->cb);
	rv = serialize_32b(obj, size);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulCounterBits);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->cb, sizeof(param->cb));
	if (rv)
		return rv;

	return rv;
}

/*
 * typedef struct CK_GCM_PARAMS {
 *	CK_BYTE_PTR       pIv;
 *	CK_ULONG          ulIvLen;
 *	CK_ULONG          ulIvBits; -> unused (deprecated?)
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulTagBits;
 * } CK_GCM_PARAMS;
 *
 * Serialized:
 * [uint32_t mechanism_id]
 * [uint32_t parameters_byte_size = 3 * 8 + IV size + AAD size]
 * [uint32_t iv_byte_size]
 * [uint8_t  iv[iv_byte_size]]
 * [uint32_t aad_byte_size]
 * [uint8_t  aad[aad_byte_size]]
 * [uint32_t tag_bit_size]
 */
static CK_RV serialize_mecha_aes_gcm(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_GCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;
	CK_ULONG aad_len;

	/* AAD is not manadatory */
	if (param->pAAD)
		aad_len = param->ulAADLen;
	else
		aad_len = 0;

	if (!param->pIv)
		return CKR_MECHANISM_PARAM_INVALID;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, 3 * sizeof(uint32_t) +
				param->ulIvLen + aad_len);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pIv, param->ulIvLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, aad_len);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, aad_len);
	if (rv)
		return rv;

	return serialize_ck_ulong(obj, param->ulTagBits);
}

/*
 * typedef struct CK_CCM_PARAMS {
 *	CK_ULONG          ulDataLen;
 *	CK_BYTE_PTR       pNonce;
 *	CK_ULONG          ulNonceLen;
 *	CK_BYTE_PTR       pAAD;
 *	CK_ULONG          ulAADLen;
 *	CK_ULONG          ulMACLen;
 *} CK_CCM_PARAMS;
 */
static CK_RV serialize_mecha_aes_ccm(struct serializer *obj,
				     CK_MECHANISM_PTR mecha)
{
	CK_CCM_PARAMS_PTR param = mecha->pParameter;
	CK_RV rv;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, 4 * sizeof(uint32_t) +
				param->ulNonceLen + param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulDataLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulNonceLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pNonce, param->ulNonceLen);
	if (rv)
		return rv;

	rv = serialize_ck_ulong(obj, param->ulAADLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, param->pAAD, param->ulAADLen);
	if (rv)
		return rv;

	return serialize_ck_ulong(obj, param->ulMACLen);
}

static CK_RV serialize_mecha_aes_iv(struct serializer *obj,
				    CK_MECHANISM_PTR mecha)
{
	uint32_t iv_size = mecha->ulParameterLen;
	CK_RV rv;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, iv_size);
	if (rv)
		return rv;

	return serialize_buffer(obj, mecha->pParameter, mecha->ulParameterLen);
}

static CK_RV serialize_mecha_ulong_param(struct serializer *obj,
					 CK_MECHANISM_PTR mecha)
{
	CK_RV rv;
	uint32_t pkcs11_data;
	CK_ULONG ck_data;

	memcpy(&ck_data, mecha->pParameter, mecha->ulParameterLen);
	pkcs11_data = ck_data;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, sizeof(uint32_t));
	if (rv)
		return rv;

	return serialize_32b(obj, pkcs11_data);
}

static CK_RV serialize_mecha_ecdh1_derive_param(struct serializer *obj,
						CK_MECHANISM_PTR mecha)
{
	CK_ECDH1_DERIVE_PARAMS *params = mecha->pParameter;
	CK_RV rv;
	size_t params_size = 3 * sizeof(uint32_t) + params->ulSharedDataLen +
				params->ulPublicDataLen;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_ec_kdf_type(params->kdf));
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulSharedDataLen);
	if (rv)
		return rv;

	rv = serialize_buffer(obj, params->pSharedData,
				params->ulSharedDataLen);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulPublicDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pPublicData,
				params->ulPublicDataLen);
}

static CK_RV serialize_mecha_ecdh_aes_key_wrap_param(struct serializer *obj,
						     CK_MECHANISM_PTR mecha)
{
	CK_ECDH_AES_KEY_WRAP_PARAMS *params = mecha->pParameter;
	CK_RV rv;
	size_t params_size = 3 * sizeof(uint32_t) + params->ulSharedDataLen;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulAESKeyBits);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_ec_kdf_type(params->kdf));
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulSharedDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pSharedData,
				params->ulSharedDataLen);
}

static CK_RV serialize_mecha_rsa_oaep_param(struct serializer *obj,
					    CK_MECHANISM_PTR mecha)
{
	CK_RSA_PKCS_OAEP_PARAMS *params = mecha->pParameter;
	CK_RV rv;
	size_t params_size = 4 * sizeof(uint32_t) + params->ulSourceDataLen;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_mechanism_type(params->hashAlg));
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_rsa_pkcs_mgf_type(params->mgf));
	if (rv)
		return rv;

	rv = serialize_32b(obj,
			   ck2ta_rsa_pkcs_oaep_source_type(params->source));
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulSourceDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, params->pSourceData,
				params->ulSourceDataLen);
}

static CK_RV serialize_mecha_rsa_pss_param(struct serializer *obj,
					   CK_MECHANISM_PTR mecha)
{
	CK_RSA_PKCS_PSS_PARAMS *params = mecha->pParameter;
	CK_RV rv;
	size_t params_size = 3 * sizeof(uint32_t);

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_mechanism_type(params->hashAlg));
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_rsa_pkcs_mgf_type(params->mgf));
	if (rv)
		return rv;

	return serialize_32b(obj, params->sLen);
}

static CK_RV serialize_mecha_rsa_aes_key_wrap_param(struct serializer *obj,
						    CK_MECHANISM_PTR mecha)
{
	CK_RSA_AES_KEY_WRAP_PARAMS *params = mecha->pParameter;
	CK_RSA_PKCS_OAEP_PARAMS *oaep_p = params->pOAEPParams;
	CK_RV rv;
	size_t params_size = 5 * sizeof(uint32_t) + params->pOAEPParams->ulSourceDataLen;

	rv = serialize_32b(obj, obj->type);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params_size);
	if (rv)
		return rv;

	rv = serialize_32b(obj, params->ulAESKeyBits);
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_mechanism_type(oaep_p->hashAlg));
	if (rv)
		return rv;

	rv = serialize_32b(obj, ck2ta_rsa_pkcs_mgf_type(oaep_p->mgf));
	if (rv)
		return rv;

	rv = serialize_32b(obj,
			   ck2ta_rsa_pkcs_oaep_source_type(oaep_p->source));
	if (rv)
		return rv;

	rv = serialize_32b(obj, oaep_p->ulSourceDataLen);
	if (rv)
		return rv;

	return serialize_buffer(obj, oaep_p->pSourceData,
				oaep_p->ulSourceDataLen);
}

/**
 * serialize_ck_mecha_params - serialize a mechanism type & params
 *
 * @obj - serializer used to track the serialization
 * @mechanism - pointer of the in structure aligned CK_MECHANISM.
 *
 * Serialized content:
 *	[mechanism-type][mechanism-param-blob]
 *
 * [mechanism-param-blob] depends on mechanism type ID, see
 * serialize_mecha_XXX().
 */
CK_RV serialize_ck_mecha_params(struct serializer *obj,
				CK_MECHANISM_PTR mechanism)
{
	CK_MECHANISM mecha;
	CK_RV rv;

	memset(obj, 0, sizeof(*obj));

	obj->object = PKCS11_CKO_MECHANISM;

	memcpy(&mecha, mechanism, sizeof(mecha));
	obj->type = ck2ta_mechanism_type(mecha.mechanism);
	if (obj->type == PKCS11_UNDEFINED_ID)
		return CKR_MECHANISM_INVALID;

	switch (mecha.mechanism) {
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_CMAC:
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA224_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_AES_XCBC_MAC:
	case CKM_AES_XCBC_MAC_96:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
		/* No parameter expected, size shall be 0 */
		if (mechanism->ulParameterLen)
			return CKR_MECHANISM_PARAM_INVALID;

		rv = serialize_32b(obj, obj->type);
		if (rv)
			return rv;

		return serialize_32b(obj, 0);

	case CKM_AES_CMAC_GENERAL:
		return serialize_mecha_ulong_param(obj, &mecha);

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
		return serialize_mecha_aes_iv(obj, &mecha);

	case CKM_AES_CTR:
		return serialize_mecha_aes_ctr(obj, &mecha);
	case CKM_AES_CCM:
		return serialize_mecha_aes_ccm(obj, &mecha);
	case CKM_AES_GCM:
		return serialize_mecha_aes_gcm(obj, &mecha);

	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		return serialize_mecha_ecdh1_derive_param(obj, &mecha);

	case CKM_ECDH_AES_KEY_WRAP:
		return serialize_mecha_ecdh_aes_key_wrap_param(obj, &mecha);

	case CKM_RSA_PKCS_OAEP:
		return serialize_mecha_rsa_oaep_param(obj, &mecha);

	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
		return serialize_mecha_rsa_pss_param(obj, &mecha);

	case CKM_RSA_AES_KEY_WRAP:
		return serialize_mecha_rsa_aes_key_wrap_param(obj, &mecha);

	default:
		return CKR_MECHANISM_INVALID;
	}
}

/*
 * Debug: dump CK attribute array to output trace
 */

static CK_RV trace_attributes(char *prefix, void *src, void *end)
{
	size_t next = 0;
	char *prefix2;
	size_t prefix_len = strlen(prefix);
	char *cur = src;

	/* append 4 spaces to the prefix */
	prefix2 = malloc(prefix_len + 1 + 4) ;
	memcpy(prefix2, prefix, prefix_len + 1);
	memset(prefix2 + prefix_len, ' ', 4);
	*(prefix2 + prefix_len + 1 + 4) = '\0';

	for (; cur < (char *)end; cur += next) {
		struct pkcs11_attribute_head ref;

		memcpy(&ref, cur, sizeof(ref));
		next = sizeof(ref) + ref.size;

		LOG_DEBUG("%s attr 0x%" PRIx32 " (%" PRIu32" byte) : %02x %02x %02x %02x ...\n",
			prefix, ref.id, ref.size,
			*((char *)cur + sizeof(ref) + 0),
			*((char *)cur + sizeof(ref) + 1),
			*((char *)cur + sizeof(ref) + 2),
			*((char *)cur + sizeof(ref) + 3));

		switch (ref.id) {
		case PKCS11_CKA_WRAP_TEMPLATE:
		case PKCS11_CKA_UNWRAP_TEMPLATE:
			serial_trace_attributes_from_head(prefix2,
							  cur + sizeof(ref));
			break;
		default:
			break;
		}
	}

	/* sanity */
	if (cur != (char *)end) {
		LOG_ERROR("unexpected none alignement\n");
	}

	free(prefix2);
	return CKR_OK;
}

CK_RV serial_trace_attributes_from_head(char *prefix, void *ref)
{
	struct pkcs11_object_head head;
	char *pre;
	CK_RV rv;

	memcpy(&head, ref, sizeof(head));

	pre = calloc(1, prefix ? strlen(prefix) + 2 : 2) ;
	if (!pre)
		return CKR_HOST_MEMORY;
	if (prefix)
		memcpy(pre, prefix, strlen(prefix));

	LOG_INFO("%s,--- (serial object) Attributes list --------\n", pre);
	LOG_INFO("%s| %" PRIu32 " item(s) - %" PRIu32 " bytes\n", pre,
		 head.attrs_count, head.attrs_size);

	pre[prefix ? strlen(prefix) + 1 : 0] = '|';

	rv = trace_attributes(pre, (char *)ref + sizeof(head),
			      (char *)ref + sizeof(head) + head.attrs_size);
	if (rv)
		goto bail;

	LOG_INFO("%s`-----------------------\n", prefix ? prefix : "");

bail:
	free(pre);
	return rv;
}

CK_RV serial_trace_attributes(char *prefix, struct serializer *obj)
{
	return serial_trace_attributes_from_head(prefix, obj->buffer);
}
