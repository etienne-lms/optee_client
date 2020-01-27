// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <pkcs11.h>
#include <stdlib.h>

#include "invoke_ta.h"
#include "local_utils.h"
#include "pkcs11_processing.h"
#include "pkcs11_token.h"
#include "ck_helpers.h"

static int lib_inited;

#define REGISTER_CK_FUNCTION(_function)		._function = _function
#define DO_NOT_REGISTER_CK_FUNCTION(_function)	._function = NULL

static const CK_FUNCTION_LIST libckteec_function_list = {
	.version = {
		.major = 2,
		.minor = 40,
	},
	REGISTER_CK_FUNCTION(C_Initialize),
	REGISTER_CK_FUNCTION(C_Finalize),
	REGISTER_CK_FUNCTION(C_GetInfo),
	REGISTER_CK_FUNCTION(C_GetFunctionList),
	REGISTER_CK_FUNCTION(C_GetSlotList),
	REGISTER_CK_FUNCTION(C_GetSlotInfo),
	REGISTER_CK_FUNCTION(C_GetTokenInfo),
	REGISTER_CK_FUNCTION(C_GetMechanismList),
	REGISTER_CK_FUNCTION(C_GetMechanismInfo),
	REGISTER_CK_FUNCTION(C_InitToken),
	REGISTER_CK_FUNCTION(C_InitPIN),
	REGISTER_CK_FUNCTION(C_SetPIN),
	REGISTER_CK_FUNCTION(C_OpenSession),
	REGISTER_CK_FUNCTION(C_CloseSession),
	REGISTER_CK_FUNCTION(C_CloseAllSessions),
	REGISTER_CK_FUNCTION(C_GetSessionInfo),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetOperationState),
	DO_NOT_REGISTER_CK_FUNCTION(C_SetOperationState),
	REGISTER_CK_FUNCTION(C_Login),
	REGISTER_CK_FUNCTION(C_Logout),
	REGISTER_CK_FUNCTION(C_CreateObject),
	DO_NOT_REGISTER_CK_FUNCTION(C_CopyObject),
	REGISTER_CK_FUNCTION(C_DestroyObject),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetObjectSize),
	REGISTER_CK_FUNCTION(C_GetAttributeValue),
	DO_NOT_REGISTER_CK_FUNCTION(C_SetAttributeValue),
	REGISTER_CK_FUNCTION(C_FindObjectsInit),
	REGISTER_CK_FUNCTION(C_FindObjects),
	REGISTER_CK_FUNCTION(C_FindObjectsFinal),
	REGISTER_CK_FUNCTION(C_EncryptInit),
	REGISTER_CK_FUNCTION(C_Encrypt),
	REGISTER_CK_FUNCTION(C_EncryptUpdate),
	REGISTER_CK_FUNCTION(C_EncryptFinal),
	REGISTER_CK_FUNCTION(C_DecryptInit),
	REGISTER_CK_FUNCTION(C_Decrypt),
	REGISTER_CK_FUNCTION(C_DecryptUpdate),
	REGISTER_CK_FUNCTION(C_DecryptFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_Digest),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestFinal),
	REGISTER_CK_FUNCTION(C_SignInit),
	REGISTER_CK_FUNCTION(C_Sign),
	REGISTER_CK_FUNCTION(C_SignUpdate),
	REGISTER_CK_FUNCTION(C_SignFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignRecoverInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignRecover),
	REGISTER_CK_FUNCTION(C_VerifyInit),
	REGISTER_CK_FUNCTION(C_Verify),
	REGISTER_CK_FUNCTION(C_VerifyUpdate),
	REGISTER_CK_FUNCTION(C_VerifyFinal),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyRecoverInit),
	DO_NOT_REGISTER_CK_FUNCTION(C_VerifyRecover),
	DO_NOT_REGISTER_CK_FUNCTION(C_DigestEncryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptDigestUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_SignEncryptUpdate),
	DO_NOT_REGISTER_CK_FUNCTION(C_DecryptVerifyUpdate),
	REGISTER_CK_FUNCTION(C_GenerateKey),
	REGISTER_CK_FUNCTION(C_GenerateKeyPair),
	DO_NOT_REGISTER_CK_FUNCTION(C_WrapKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_UnwrapKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_DeriveKey),
	DO_NOT_REGISTER_CK_FUNCTION(C_SeedRandom),
	DO_NOT_REGISTER_CK_FUNCTION(C_GenerateRandom),
	DO_NOT_REGISTER_CK_FUNCTION(C_GetFunctionStatus),
	DO_NOT_REGISTER_CK_FUNCTION(C_CancelFunction),
	DO_NOT_REGISTER_CK_FUNCTION(C_WaitForSlotEvent),
};

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	/* Argument currently unused as per the PKCS#11 specification */
	(void)pInitArgs;

	if (lib_inited)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (ta_invoke_init())
		return CKR_FUNCTION_FAILED;

	lib_inited = 1;

	return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	/* Argument currently unused as per the PKCS#11 specification */
	(void)pReserved;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	sks_invoke_terminate();

	lib_inited = 0;

	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return sks_ck_get_info(pInfo);
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	/* Discard the const attribute when exporting the list address */
	*ppFunctionList = (void *)&libckteec_function_list;

	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
		    CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_slot_get_list(tokenPresent, pSlotList, pulCount);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
		    CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_slot_get_info(slotID, pInfo);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SLOT_ID_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_UTF8CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_init_token(slotID, pPin, ulPinLen, pLabel);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_PIN_INCORRECT:
	case CKR_PIN_LOCKED:
	case CKR_SESSION_EXISTS:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_TOKEN_WRITE_PROTECTED:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID,
		     CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_token_get_info(slotID, pInfo);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_token_mechanism_ids(slotID, pMechanismList, pulCount);

	switch (rv) {
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_token_mechanism_info(slotID, type, pInfo);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_MECHANISM_INVALID:
	case CKR_OK:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,
		    CK_FLAGS flags,
		    CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (flags & ~(CKF_RW_SESSION | CKF_SERIAL_SESSION))
		return CKR_ARGUMENTS_BAD;

	/* Specific mandated flag */
	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	rv = sks_ck_open_session(slotID, flags, pApplication, Notify, phSession);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SESSION_COUNT:
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
	case CKR_TOKEN_NOT_RECOGNIZED:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_close_session(hSession);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_close_all_sessions(slotID);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SLOT_ID_INVALID:
	case CKR_TOKEN_NOT_PRESENT:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
		       CK_SESSION_INFO_PTR pInfo)
{
	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return sks_ck_get_session_info(hSession, pInfo);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_init_pin(hSession, pPin, ulPinLen);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_READ_ONLY:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_USER_NOT_LOGGED_IN:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_UTF8CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_set_pin(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_MECHANISM_INVALID:
	case CKR_OK:
	case CKR_PIN_INCORRECT:
	case CKR_PIN_INVALID:
	case CKR_PIN_LEN_RANGE:
	case CKR_PIN_LOCKED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_ARGUMENTS_BAD:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,
	      CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin,
	      CK_ULONG ulPinLen)

{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_login(hSession, userType, pPin, ulPinLen);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_PIN_INCORRECT:
	case CKR_PIN_LOCKED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY_EXISTS:
	case CKR_USER_ALREADY_LOGGED_IN:
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
	case CKR_USER_PIN_NOT_INITIALIZED:
	case CKR_USER_TOO_MANY_TYPES:
	case CKR_USER_TYPE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = sks_ck_logout(hSession);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession;
	(void)pOperationState;
	(void)ulOperationStateLen;
	(void)hEncryptionKey;
	(void)hAuthenticationKey;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
		     CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount,
		     CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_create_object(hSession, pTemplate, ulCount, phObject);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_READ_ONLY:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_CURVE_NOT_SUPPORTED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_DOMAIN_PARAMS_INVALID:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TEMPLATE_INCOMPLETE:
	case CKR_TEMPLATE_INCONSISTENT:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
		   CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate,
		   CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	(void)phNewObject;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_destroy_object(hSession, hObject);

	switch (rv) {
	case CKR_ACTION_PROHIBITED:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OBJECT_HANDLE_INVALID:
	case CKR_OK:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TOKEN_WRITE_PROTECTED:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
		      CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	(void)hSession;
	(void)hObject;
	(void)pulSize;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_get_attribute_value(hSession, hObject, pTemplate, ulCount);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
			  CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
			CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_find_objects_init(hSession, pTemplate, ulCount);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount,
		    CK_ULONG_PTR pulObjectCount)

{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_find_objects(hSession, phObject,
			     ulMaxObjectCount, pulObjectCount);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_find_objects_final(hSession);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_init(hSession, pMechanism, hKey, CK_FALSE);

	switch (rv) {
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_oneshot(hSession, pData, ulDataLen,
				   pEncryptedData, pulEncryptedDataLen,
				   CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedData,
		      CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_update(hSession, pPart, ulPartLen,
				  pEncryptedData,
				  pulEncryptedDataLen, CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_final(hSession, pLastEncryptedPart,
				 pulLastEncryptedPartLen, CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_init(hSession, pMechanism, hKey, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_oneshot(hSession, pEncryptedData,
				   ulEncryptedDataLen,
				   pData, pulDataLen, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_ENCRYPTED_DATA_INVALID:
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_update(hSession, pEncryptedPart,
				  ulEncryptedPartLen,
				  pPart, pulPartLen, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_ENCRYPTED_DATA_INVALID:
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_encdecrypt_final(hSession, pLastPart, pulLastPartLen, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_ENCRYPTED_DATA_INVALID:
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}


CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism)
{
	(void)hSession;
	(void)pMechanism;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pDigest;
	(void)pulDigestLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,
		  CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)hKey;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pDigest;
	(void)pulDigestLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
		 CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_init(hSession, pMechanism, hKey, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
	     CK_BYTE_PTR pData,
	     CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature,
	     CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_oneshot(hSession, pData, ulDataLen,
				   pSignature, pulSignatureLen,
				   CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_INVALID:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
	case CKR_FUNCTION_REJECTED:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_update(hSession, pPart, ulPartLen, CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
		  CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_final(hSession, pSignature, pulSignatureLen,
				 CK_TRUE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
	case CKR_FUNCTION_REJECTED:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	rv = ck_signverify_init(hSession, pMechanism, hKey, CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen,
	       CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	CK_ULONG out_size = ulSignatureLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_oneshot(hSession, pData, ulDataLen,
				   pSignature, &out_size,
				   CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_INVALID:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SIGNATURE_INVALID:
	case CKR_SIGNATURE_LEN_RANGE:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
		     CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_update(hSession, pPart, ulPartLen, CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_signverify_final(hSession, pSignature, &ulSignatureLen,
				 CK_FALSE);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_DATA_LEN_RANGE:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_OK:
	case CKR_OPERATION_NOT_INITIALIZED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SIGNATURE_INVALID:
	case CKR_SIGNATURE_LEN_RANGE:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen,
		      CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	(void)pData;
	(void)pulDataLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen,
			  CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen,
			    CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate,
		    CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_generate_key(hSession, pMechanism, pTemplate, ulCount,
			     phKey);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_READ_ONLY:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_CURVE_NOT_SUPPORTED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TEMPLATE_INCOMPLETE:
	case CKR_TEMPLATE_INCONSISTENT:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;
	CK_ATTRIBUTE_PTR pub_attribs_n = NULL;
	CK_ATTRIBUTE_PTR priv_attribs_n = NULL;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_guess_key_type(pMechanism, pPublicKeyTemplate,
			       &ulPublicKeyAttributeCount, &pub_attribs_n);
	if (rv != CKR_OK)
		goto bail;

	rv = ck_guess_key_type(pMechanism, pPrivateKeyTemplate,
			       &ulPrivateKeyAttributeCount, &priv_attribs_n);
	if (rv != CKR_OK)
		goto bail;

	rv = ck_generate_key_pair(hSession, pMechanism,
				  pub_attribs_n, ulPublicKeyAttributeCount,
				  priv_attribs_n, ulPrivateKeyAttributeCount,
				  phPublicKey, phPrivateKey);

bail:
	if (pub_attribs_n)
		free(pub_attribs_n);
	if (priv_attribs_n)
		free(priv_attribs_n);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_READ_ONLY:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_CURVE_NOT_SUPPORTED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_DOMAIN_PARAMS_INVALID:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TEMPLATE_INCOMPLETE:
	case CKR_TEMPLATE_INCONSISTENT:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)hSession;
	(void)pMechanism;
	(void)hWrappingKey;
	(void)hKey;
	(void)pWrappedKey;
	(void)pulWrappedKeyLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey,
		  CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hUnwrappingKey;
	(void)pWrappedKey;
	(void)ulWrappedKeyLen;
	(void)pTemplate;
	(void)ulCount;
	(void)phKey;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey,
		  CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulCount,
		  CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	rv = ck_derive_key(hSession, pMechanism, hBaseKey, pTemplate,
				   ulCount, phKey);

	switch (rv) {
	case CKR_ARGUMENTS_BAD:
	case CKR_ATTRIBUTE_READ_ONLY:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_VALUE_INVALID:
	case CKR_CRYPTOKI_NOT_INITIALIZED:
	case CKR_CURVE_NOT_SUPPORTED:
	case CKR_DEVICE_ERROR:
	case CKR_DEVICE_MEMORY:
	case CKR_DEVICE_REMOVED:
	case CKR_DOMAIN_PARAMS_INVALID:
	case CKR_FUNCTION_CANCELED:
	case CKR_FUNCTION_FAILED:
	case CKR_GENERAL_ERROR:
	case CKR_HOST_MEMORY:
	case CKR_KEY_HANDLE_INVALID:
	case CKR_KEY_SIZE_RANGE:
	case CKR_KEY_TYPE_INCONSISTENT:
	case CKR_MECHANISM_INVALID:
	case CKR_MECHANISM_PARAM_INVALID:
	case CKR_OK:
	case CKR_OPERATION_ACTIVE:
	case CKR_PIN_EXPIRED:
	case CKR_SESSION_CLOSED:
	case CKR_SESSION_HANDLE_INVALID:
	case CKR_SESSION_READ_ONLY:
	case CKR_TEMPLATE_INCOMPLETE:
	case CKR_TEMPLATE_INCONSISTENT:
	case CKR_TOKEN_WRITE_PROTECTED:
	case CKR_USER_NOT_LOGGED_IN:
		break;
	default:
		assert(!rv);
	}

	return rv;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
		   CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	(void)hSession;
	(void)pSeed;
	(void)ulSeedLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
		       CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	(void)hSession;
	(void)pRandomData;
	(void)ulRandomLen;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
			 CK_SLOT_ID_PTR slotID,
			 CK_VOID_PTR pReserved)
{
	(void)flags;
	(void)slotID;
	(void)pReserved;

	if (!lib_inited)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
