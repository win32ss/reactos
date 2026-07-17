/*
 * User-mode functions of the SChannel security provider
 *
 * Copyright 2007 Yuval Fledel
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "sspi.h"
#include "ntsecapi.h"
#include "ntsecpkg.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(schannel);

SECURITY_STATUS SEC_ENTRY schan_QueryContextAttributesW(
        PCtxtHandle context_handle, ULONG attribute, PVOID buffer);

SECURITY_STATUS SEC_ENTRY schan_DecryptMessage(PCtxtHandle context_handle,
        PSecBufferDesc message, ULONG message_seq_no, PULONG quality);

SECURITY_STATUS SEC_ENTRY schan_EncryptMessage(PCtxtHandle context_handle,
        ULONG quality, PSecBufferDesc message, ULONG message_seq_no);

SECURITY_STATUS SEC_ENTRY schan_InitializeSecurityContextW(
 PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR *pszTargetName,
 ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
 PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
 PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry);

NTSTATUS
NTAPI
SpInstanceInit(
    _In_ ULONG Version,
    _In_ PSECPKG_DLL_FUNCTIONS FunctionTable,
    _Inout_ PVOID *UserFunctions)
{
    TRACE("SpInstanceInit(Version 0x%lx, 0x%p, 0x%p)\n",
          Version, FunctionTable, UserFunctions);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SpInitUmContextFn(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _In_ PSecBuffer PackedContext)
{
    TRACE("SpInstanceInit(0x%p, 0x%p)\n",
          ContextHandle, PackedContext);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SpDeleteUmContextFn(
    _In_ LSA_SEC_HANDLE ContextHandle)
{
    TRACE("SpInstanceInit(0x%p, 0x%p)\n",
          ContextHandle);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
UsrSpMakeSignature(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _In_ ULONG QualityOfProtection,
    _Inout_ PSecBufferDesc MessageBuffers,
    _In_ ULONG MessageSequenceNumber)
{
    TRACE("UsrSpMakeSignature(0x%p 0x%x 0x%p 0x%x)\n",
          ContextHandle, QualityOfProtection,
          MessageBuffers, MessageSequenceNumber);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsrSpVerifySignature(
    _In_ LSA_SEC_HANDLE phContext,
    _In_ PSecBufferDesc pMessage,
    _In_ ULONG MessageSeqNo,
    _In_ PULONG pfQOP)
{
    TRACE("UsrSpVerifySignature(0x%p 0x%x 0x%x 0x%p)\n",
          phContext, pMessage, MessageSeqNo, pfQOP);

    return ERROR_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
UsrSpSealMessage(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _In_ ULONG QualityOfProtection,
    _Inout_ PSecBufferDesc MessageBuffers,
    _In_ ULONG MessageSequenceNumber)
{
    TRACE("UsrSpSealMessage(0x%p 0x%x 0x%p 0x%x)\n",
          ContextHandle, QualityOfProtection,
          MessageBuffers, MessageSequenceNumber);
    CtxtHandle CtxHandle;
    CtxHandle.dwLower = ContextHandle;
    CtxHandle.dwUpper = 0;
    return schan_EncryptMessage(&CtxHandle, QualityOfProtection, MessageBuffers,
                                MessageSequenceNumber);
}

NTSTATUS
NTAPI
UsrSpUnsealMessage(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _Inout_ PSecBufferDesc MessageBuffers,
    _In_ ULONG MessageSequenceNumber,
    _In_ PULONG QualityOfProtection)
{
    TRACE("UsrSpUnsealMessage(0x%p 0x%x 0x%p 0x%x)\n",
          ContextHandle, MessageBuffers,
          MessageSequenceNumber, QualityOfProtection);
    CtxtHandle CtxHandle;
    CtxHandle.dwLower = ContextHandle;
    CtxHandle.dwUpper = 0;
    return schan_DecryptMessage(&CtxHandle, MessageBuffers, MessageSequenceNumber,
                                QualityOfProtection);
}

NTSTATUS
NTAPI
UsrSpGetContextToken(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _Inout_ PHANDLE ImpersonationToken)
{
    TRACE("UsrSpGetContextToken(0x%p 0x%p)\n",
          ContextHandle, ImpersonationToken);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsrSpQueryContextAttributes(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _In_ ULONG ContextAttribute,
    _Inout_ PVOID Buffer)
{
    TRACE("UsrSpQueryContextAttributes(0x%p 0x%x 0x%p)\n",
            ContextHandle, ContextAttribute, Buffer);
    CtxtHandle CtxHandle;
    CtxHandle.dwLower = ContextHandle;
    CtxHandle.dwUpper = 0;
    return schan_QueryContextAttributesW(&CtxHandle, ContextAttribute, Buffer);
}

NTSTATUS
NTAPI
UsrSpCompleteAuthToken(
    _In_ LSA_SEC_HANDLE ContextHandle,
    _In_ PSecBufferDesc InputBuffer)
{
    TRACE("UsrSpCompleteAuthToken(0x%p 0x%p)\n",
          ContextHandle, InputBuffer);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsrSpDeleteUserModeContext(
    _In_ LSA_SEC_HANDLE ContextHandle)
{
    TRACE("UsrSpDeleteUserModeContext(0x%p)\n",
          ContextHandle);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
UsrSpFormatCredentials(
    _In_ PSecBuffer Credentials,
    _Inout_ PSecBuffer FormattedCredentials)
{
    TRACE("UsrSpFormatCredentials(0x%p 0x%p)\n",
          Credentials, FormattedCredentials);

    return ERROR_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
UsrSpMarshallSupplementalCreds(
    _In_ ULONG CredentialSize,
    _In_ PUCHAR Credentials,
    _Inout_ PULONG MarshalledCredSize,
    _Inout_ PVOID *MarshalledCreds)
{
    TRACE("UsrSpMarshallSupplementalCreds(0x%x 0x%p 0x%p 0x%p)\n",
          CredentialSize, Credentials, MarshalledCredSize, MarshalledCreds);

    return ERROR_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
UsrSpExportSecurityContext(
    _In_ LSA_SEC_HANDLE phContext,
    _In_ ULONG fFlags,
    _Inout_ PSecBuffer pPackedContext,
    _Inout_ PHANDLE pToken)
{
    TRACE("UsrSpExportSecurityContext(0x%p 0x%x 0x%p 0x%p)\n",
          phContext, fFlags, pPackedContext, pToken);

    return ERROR_NOT_SUPPORTED;
}

NTSTATUS
NTAPI
UsrSpImportSecurityContext(
    _In_ PSecBuffer pPackedContext,
    _In_ HANDLE Token,
    _Inout_ PLSA_SEC_HANDLE phContext)
{
    TRACE("UsrSpImportSecurityContext(0x%p 0x%x 0x%p)\n",
          pPackedContext, Token, phContext);

    return ERROR_NOT_SUPPORTED;
}

static SECPKG_USER_FUNCTION_TABLE secPkgUserTables[2] =
{ {
    SpInstanceInit, /* InstanceInit */
    SpInitUmContextFn, /* InitUserModeContext */
    NULL, /* MakeSignature */
    NULL, /* VerifySignature */
    UsrSpSealMessage, /* SealMessage */
    UsrSpUnsealMessage, /* UnsealMessage */
    NULL, /* GetContextToken */
    UsrSpQueryContextAttributes, /* SpQueryContextAttributes */
    NULL, /* CompleteAuthToken */
    SpDeleteUmContextFn, /* DeleteUserModeContext */
    NULL, /* FormatCredentials */
    NULL, /* MarshallSupplementalCreds */
    NULL, /* ExportContext */
    NULL, /* ImportContext */
  }, {
    SpInstanceInit, /* InstanceInit */
    SpInitUmContextFn, /* InitUserModeContext */
    NULL, /* MakeSignature */
    NULL, /* VerifySignature */
    UsrSpSealMessage, /* SealMessage */
    UsrSpUnsealMessage, /* UnsealMessage */
    NULL, /* GetContextToken */
    UsrSpQueryContextAttributes, /* SpQueryContextAttributes */
    NULL, /* CompleteAuthToken */
    SpDeleteUmContextFn, /* DeleteUserModeContext */
    NULL, /* FormatCredentials */
    NULL, /* MarshallSupplementalCreds */
    NULL, /* ExportContext */
    NULL, /* ImportContext */
  }
};

/***********************************************************************
 *              SpUserModeInitialize (SCHANNEL.@)
 */
NTSTATUS WINAPI SpUserModeInitialize(ULONG LsaVersion, PULONG PackageVersion,
  PSECPKG_USER_FUNCTION_TABLE *ppTables, PULONG pcTables)
{
    TRACE("(%u, %p, %p, %p)\n", LsaVersion, PackageVersion, ppTables, pcTables);

    if (LsaVersion != SECPKG_INTERFACE_VERSION)
        return STATUS_INVALID_PARAMETER;

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *pcTables = 2;
    *ppTables = secPkgUserTables;

    return STATUS_SUCCESS;
}
