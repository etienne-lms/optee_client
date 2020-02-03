/*
 * Copyright (c) 2017-2020, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <pkcs11.h>
#include <ck_debug.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string.h>

#include "ck_helpers.h"
#include "invoke_ta.h"
#include "invoke_ta2.h"
#include "local_utils.h"
#include "pkcs11_token.h"

#define PKCS11_SLOT_MANUFACTURER		"Linaro"

#define PADDED_STRING_COPY(_dst, _src) \
	do { \
		memset((char *)_dst, ' ', sizeof(_dst)); \
		strncpy((char *)_dst, _src, sizeof(_dst)); \
	} while (0)

/**
 * ck_get_info - implementation of C_GetInfo
 */
int ck_get_info(CK_INFO_PTR info)
{
	const CK_VERSION ck_version = { 2, 40 };
	const char manuf_id[] = PKCS11_SLOT_MANUFACTURER; // TODO slot?
	const CK_FLAGS flags = 0;	/* must be zero per the PKCS#11 2.40 */
	const char lib_description[] = "OP-TEE PKCS11 Cryptoki client library";
	const CK_VERSION lib_version = { 0, 0 };

	if (!info)
		return CKR_ARGUMENTS_BAD;

	info->cryptokiVersion = ck_version;
	PADDED_STRING_COPY(info->manufacturerID, manuf_id);
	info->flags = flags;
	PADDED_STRING_COPY(info->libraryDescription, lib_description);
	info->libraryVersion = lib_version;

	return CKR_OK;
}

/**
 * ck_slot_get_list - Wrap C_GetSlotList into PKCS11_CMD_SLOT_LIST
 */
CK_RV ck_slot_get_list(CK_BBOOL present,
		       CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	TEEC_SharedMemory *shm;
	size_t size = 0;
	CK_RV rv = CKR_GENERAL_ERROR;
	unsigned int n;

	/* Discard present: all are present */
	(void)present;

	if (!count || (*count && !slots))
		return CKR_ARGUMENTS_BAD;

	if (ck_invoke_ta_in_out(NULL, PKCS11_CMD_SLOT_LIST, NULL, 0,
				NULL, 0, NULL, &size) != CKR_BUFFER_TOO_SMALL)
		return CKR_DEVICE_ERROR;

	if (!slots || *count < (size / sizeof(uint32_t))) {
		*count = size / sizeof(uint32_t);
		if (!slots)
			return CKR_OK;

		return CKR_BUFFER_TOO_SMALL;
	}

	shm = sks_alloc_shm_out(NULL, size);
	if (!shm)
		return CKR_HOST_MEMORY;

	if (ck_invoke_ta_in_out(NULL, PKCS11_CMD_SLOT_LIST, NULL, 0,
				NULL, 0, shm, NULL) != CKR_OK) {
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	for (n = 0; n < (size / sizeof(uint32_t)); n++)
		slots[n] = *((uint32_t *)shm->buffer + n);

	*count = size / sizeof(uint32_t);
	rv = CKR_OK;
bail:
	sks_free_shm(shm);
	return rv;

}

/**
 * ck_slot_get_info - Wrap C_GetSlotInfo into PKCS11_CMD_SLOT_INFO
 */
int ck_slot_get_info(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info)
{
	uint32_t ctrl[1] = { slot };
	CK_SLOT_INFO *ck_info = info;
	struct pkcs11_slot_info pkcs11_info;
	size_t out_size = sizeof(pkcs11_info);

	if (!info)
		return CKR_ARGUMENTS_BAD;

	if (ck_invoke_ta_in_out(NULL, PKCS11_CMD_SLOT_INFO, &ctrl, sizeof(ctrl),
				NULL, 0, &pkcs11_info, &out_size))
		return CKR_DEVICE_ERROR;

	if (ta2ck_slot_info(ck_info, &pkcs11_info)) {
		LOG_ERROR("unexpected bad token info structure\n");
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
}

/**
 * ck_token_get_info - Wrap C_GetTokenInfo into PKCS11_CMD_TOKEN_INFO
 */
CK_RV ck_token_get_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	uint32_t ctrl[1] = { slot };
	CK_TOKEN_INFO *ck_info = info;
	TEEC_SharedMemory *shm;
	size_t size;
	CK_RV rv = CKR_GENERAL_ERROR;

	if (!info)
		return CKR_ARGUMENTS_BAD;

	ctrl[0] = (uint32_t)slot;
	size = 0;
	if (ck_invoke_ta_in_out(NULL, PKCS11_CMD_TOKEN_INFO, ctrl, sizeof(ctrl),
				NULL, 0, NULL, &size) != CKR_BUFFER_TOO_SMALL)
		return CKR_DEVICE_ERROR;

	shm = sks_alloc_shm_out(NULL, size);
	if (!shm)
		return CKR_HOST_MEMORY;

	ctrl[0] = (uint32_t)slot;
	rv = ck_invoke_ta_in_out(NULL, PKCS11_CMD_TOKEN_INFO,
				 ctrl, sizeof(ctrl), NULL, 0, shm, NULL);
	if (rv)
		goto bail;

	if (shm->size < sizeof(struct pkcs11_token_info)) {
		LOG_ERROR("unexpected bad token info size\n");
		rv = CKR_DEVICE_ERROR;
		goto bail;
	}

	rv = ta2ck_token_info(ck_info, shm->buffer);

bail:
	sks_free_shm(shm);

	return rv;
}

/**
 * ck_init_token - Wrap C_InitToken into PKCS11_CMD_INIT_TOKEN
 */
CK_RV ck_init_token(CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
		    CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	uint32_t pkcs11_slot = slot;
	uint32_t pkcs11_pin_len = pin_len;
	size_t ctrl_size = 2 * sizeof(uint32_t) + pkcs11_pin_len +
			   32 * sizeof(uint8_t);
	char *ctrl;
	size_t offset;

	if (!pin || !label)
		return CKR_ARGUMENTS_BAD;

	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &pkcs11_slot, sizeof(uint32_t));
	offset = sizeof(uint32_t);

	memcpy(ctrl + offset, &pkcs11_pin_len, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	memcpy(ctrl + offset, pin, pkcs11_pin_len);
	offset += pkcs11_pin_len;

	memcpy(ctrl + offset, label, 32 * sizeof(uint8_t));

	return ck_invoke_ta(NULL, PKCS11_CMD_INIT_TOKEN, ctrl, ctrl_size);
}

/**
 * ck_token_mechanism_ids - Wrap C_GetMechanismList
 */
CK_RV ck_token_mechanism_ids(CK_SLOT_ID slot,
			     CK_MECHANISM_TYPE_PTR mechanisms,
			     CK_ULONG_PTR count)
{
	uint32_t ctrl[1] = { slot };
	size_t outsize = *count * sizeof(uint32_t);
	void *outbuf = NULL;
	CK_RV rv;

	if (!count || (*count && !mechanisms))
		return CKR_ARGUMENTS_BAD;

	if (mechanisms) {
		outbuf = malloc(outsize);
		if (!outbuf)
			return CKR_HOST_MEMORY;
	}

	rv = ck_invoke_ta_in_out(NULL, PKCS11_CMD_MECHANISM_IDS,
				 &ctrl, sizeof(ctrl),
				 NULL, 0, outbuf, &outsize);

	if (rv == CKR_OK || rv == CKR_BUFFER_TOO_SMALL) {
		*count = outsize / sizeof(uint32_t);
	}
	if (!mechanisms && rv == CKR_BUFFER_TOO_SMALL) {
		rv = CKR_OK;
		goto bail;
	}
	if (rv) {
		goto bail;
	}

	if (ta2ck_mechanism_type_list(mechanisms, outbuf, *count)) {
		LOG_ERROR("unexpected bad mechanism_type list\n");
		rv = CKR_DEVICE_ERROR;
	}

bail:
	free(outbuf);

	return rv;
}

/**
 * ck_token_mechanism_info - Wrap C_GetMechanismInfo into command MECHANISM_INFO
 */
CK_RV ck_token_mechanism_info(CK_SLOT_ID slot,
			      CK_MECHANISM_TYPE type,
			      CK_MECHANISM_INFO_PTR info)
{
	CK_RV rv;
	uint32_t ctrl[2];
	struct pkcs11_mechanism_info outbuf;
	size_t outsize = sizeof(outbuf);

	if (!info)
		return CKR_ARGUMENTS_BAD;

	ctrl[0] = (uint32_t)slot;
	ctrl[1] = ck2ta_mechanism_type(type);
	if (ctrl[1] == PKCS11_UNDEFINED_ID) {
		LOG_ERROR("mechanism is not support by this library\n");
		return CKR_DEVICE_ERROR;
	}

	/* info is large enought, for sure */
	rv = ck_invoke_ta_in_out(NULL, PKCS11_CMD_MECHANISM_INFO,
				 &ctrl, sizeof(ctrl),
				 NULL, 0, &outbuf, &outsize);
	if (rv) {
		LOG_ERROR("Unexpected bad state (%x)\n", (unsigned)rv);
		return CKR_DEVICE_ERROR;
	}

	if (ta2ck_mechanism_info(info, &outbuf)) {
		LOG_ERROR("unexpected bad mechanism info structure\n");
		rv = CKR_DEVICE_ERROR;
	}
	return rv;
}

/**
 * ck_open_session - Wrap C_OpenSession into PKCS11_CMD_OPEN_{RW|RO}_SESSION
 */
CK_RV ck_open_session(CK_SLOT_ID slot, CK_FLAGS flags,
		      CK_VOID_PTR cookie, CK_NOTIFY callback,
		      CK_SESSION_HANDLE_PTR session)
{
	uint32_t ctrl[1] = { slot };
	unsigned long cmd;
	uint32_t handle;
	size_t out_sz = sizeof(handle);
	CK_RV rv;

	if ((flags & ~(CKF_RW_SESSION | CKF_SERIAL_SESSION)) ||
	    !session)
		return CKR_ARGUMENTS_BAD;

	/* Specific mandated flag */
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (cookie || callback) {
		LOG_ERROR("C_OpenSession does not handle callback yet\n");
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (flags & CKF_RW_SESSION)
		cmd = PKCS11_CMD_OPEN_RW_SESSION;
	else
		cmd = PKCS11_CMD_OPEN_RO_SESSION;

	rv = ck_invoke_ta_in_out(NULL, cmd, &ctrl, sizeof(ctrl),
				 NULL, 0, &handle, &out_sz);
	if (rv)
		return rv;

	*session = handle;

	return CKR_OK;
}

/**
 * ck_open_session - Wrap C_OpenSession into PKCS11_CMD_CLOSE_SESSION
 */
CK_RV ck_close_session(CK_SESSION_HANDLE session)
{
	uint32_t ctrl[1] = { (uint32_t)session };

	return ck_invoke_ta(NULL, PKCS11_CMD_CLOSE_SESSION,
			    &ctrl, sizeof(ctrl));
}

/**
 * ck_close_all_sessions - Wrap C_CloseAllSessions into TA command
 */
CK_RV ck_close_all_sessions(CK_SLOT_ID slot)
{
	uint32_t ctrl[1] = { (uint32_t)slot };

	return ck_invoke_ta(NULL, PKCS11_CMD_CLOSE_ALL_SESSIONS,
			    &ctrl, sizeof(ctrl));
}

/**
 * ck_get_session_info - Wrap C_GetSessionInfo into PKCS11_CMD_SESSION_INFO
 */
CK_RV ck_get_session_info(CK_SESSION_HANDLE session,
			  CK_SESSION_INFO_PTR info)
{
	uint32_t ctrl[1] = { (uint32_t)session };
	size_t info_size = sizeof(CK_SESSION_INFO);

	if (!info)
		return CKR_ARGUMENTS_BAD;

	return ck_invoke_ta_in_out(NULL, PKCS11_CMD_SESSION_INFO,
				   &ctrl, sizeof(ctrl),
				   NULL, 0, info, &info_size);
}

/**
 * ck_init_pin - Wrap C_InitPIN into PKCS11_CMD_INIT_PIN
 */
CK_RV ck_init_pin(CK_SESSION_HANDLE session,
		  CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	uint32_t pkcs11_session = session;
	uint32_t pkcs11_pin_len = pin_len;
	size_t ctrl_size = 2 * sizeof(uint32_t) + pkcs11_pin_len;
	char *ctrl;

	if (!pin)
		return CKR_ARGUMENTS_BAD;

	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	/* ABI: [session][pin_len][pin] */
	memcpy(ctrl, &pkcs11_session, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), &pkcs11_pin_len, sizeof(uint32_t));
	memcpy(ctrl + 2 * sizeof(uint32_t), pin, pkcs11_pin_len);

	return ck_invoke_ta(NULL, PKCS11_CMD_INIT_PIN, ctrl, ctrl_size);
}

/**
 * ck_set_pin - Wrap C_SetPIN into PKCS11_CMD_SET_PIN
 */
CK_RV ck_set_pin(CK_SESSION_HANDLE session,
		 CK_UTF8CHAR_PTR old, CK_ULONG old_len,
		 CK_UTF8CHAR_PTR new, CK_ULONG new_len)
{
	uint32_t pkcs11_session = session;
	uint32_t pkcs11_old_len = old_len;
	uint32_t pkcs11_new_len = new_len;
	size_t ctrl_size = 3 * sizeof(uint32_t) + pkcs11_old_len + pkcs11_new_len;
	char *ctrl;
	size_t offset;

	if (!old || !new)
		return CKR_ARGUMENTS_BAD;

	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	/* ABI: [session][old_pin_len][new_pin_len][old pin][new pin] */
	memcpy(ctrl, &pkcs11_session, sizeof(uint32_t));
	offset = sizeof(uint32_t);

	memcpy(ctrl + offset, &pkcs11_old_len, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	memcpy(ctrl + offset, &pkcs11_new_len, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	memcpy(ctrl + offset, old, pkcs11_old_len);
	offset += pkcs11_old_len;

	memcpy(ctrl + offset, new, pkcs11_new_len);

	return ck_invoke_ta(NULL, PKCS11_CMD_SET_PIN, ctrl, ctrl_size);
}

/**
 * ck_login - Wrap C_Login into PKCS11_CMD_LOGIN
 */
CK_RV ck_login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
	       CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)

{
	uint32_t pkcs11_session = session;
	uint32_t pkcs11_user = ck2ta_user_type(user_type);
	uint32_t pkcs11_pin_len = pin_len;
	size_t ctrl_size = 3 * sizeof(uint32_t) + pkcs11_pin_len;
	char *ctrl;

	if (!pin)
		return CKR_ARGUMENTS_BAD;

	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &pkcs11_session, sizeof(uint32_t));
	memcpy(ctrl + sizeof(uint32_t), &pkcs11_user, sizeof(uint32_t));
	memcpy(ctrl + 2 * sizeof(uint32_t), &pkcs11_pin_len, sizeof(uint32_t));
	memcpy(ctrl + 3 * sizeof(uint32_t), pin, pkcs11_pin_len);

	return ck_invoke_ta(NULL, PKCS11_CMD_LOGIN, ctrl, ctrl_size);
}

/**
 * ck_logout - Wrap C_Logout into PKCS11_CMD_LOGOUT
 */
CK_RV ck_logout(CK_SESSION_HANDLE session)
{
	uint32_t pkcs11_session = session;
	size_t ctrl_size = sizeof(uint32_t);
	char *ctrl;

	ctrl = malloc(ctrl_size);
	if (!ctrl)
		return CKR_HOST_MEMORY;

	memcpy(ctrl, &pkcs11_session, sizeof(uint32_t));

	return ck_invoke_ta(NULL, PKCS11_CMD_LOGOUT, ctrl, ctrl_size);
}
