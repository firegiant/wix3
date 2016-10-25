// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

#include "precomp.h"


static HRESULT AddUserToGroup(
    __in LPWSTR wzUser,
    __in LPCWSTR wzUserDomain,
    __in LPCWSTR wzGroup,
    __in LPCWSTR wzGroupDomain
    )
{
    Assert(wzUser && *wzUser && wzUserDomain && wzGroup && *wzGroup && wzGroupDomain);

    HRESULT hr = S_OK;
    IADsGroup *pGroup = NULL;
    BSTR bstrUser = NULL;
    BSTR bstrGroup = NULL;
    LPCWSTR wz = NULL;
    LPWSTR pwzUser = NULL;
    LOCALGROUP_MEMBERS_INFO_3 lgmi;

    if (*wzGroupDomain)
    {
        wz = wzGroupDomain;
    }

    // Try adding it to the global group first
    UINT ui = ::NetGroupAddUser(wz, wzGroup, wzUser);
    if (NERR_GroupNotFound == ui)
    {
        // Try adding it to the local group
        if (wzUserDomain)
        {
            hr = StrAllocFormatted(&pwzUser, L"%s\\%s", wzUserDomain, wzUser);
            ExitOnFailure(hr, "failed to allocate user domain string");
        }

        lgmi.lgrmi3_domainandname = (NULL == pwzUser ? wzUser : pwzUser);
        ui = ::NetLocalGroupAddMembers(wz, wzGroup, 3 , reinterpret_cast<LPBYTE>(&lgmi), 1);
    }
    hr = HRESULT_FROM_WIN32(ui);
    if (HRESULT_FROM_WIN32(ERROR_MEMBER_IN_ALIAS) == hr) // if they're already a member of the group don't report an error
        hr = S_OK;

    //
    // If we failed, try active directory
    //
    if (FAILED(hr))
    {
        WcaLog(LOGMSG_VERBOSE, "Failed to add user: %ls, domain %ls to group: %ls, domain: %ls with error 0x%x.  Attempting to use Active Directory", wzUser, wzUserDomain, wzGroup, wzGroupDomain, hr);

        hr = UserCreateADsPath(wzUserDomain, wzUser, &bstrUser);
        ExitOnFailure2(hr, "failed to create user ADsPath for user: %ls domain: %ls", wzUser, wzUserDomain);

        hr = UserCreateADsPath(wzGroupDomain, wzGroup, &bstrGroup);
        ExitOnFailure2(hr, "failed to create group ADsPath for group: %ls domain: %ls", wzGroup, wzGroupDomain);

        hr = ::ADsGetObject(bstrGroup,IID_IADsGroup, reinterpret_cast<void**>(&pGroup));
        ExitOnFailure1(hr, "Failed to get group '%ls'.", reinterpret_cast<WCHAR*>(bstrGroup) );

        hr = pGroup->Add(bstrUser);
        if ((HRESULT_FROM_WIN32(ERROR_OBJECT_ALREADY_EXISTS) == hr) || (HRESULT_FROM_WIN32(ERROR_MEMBER_IN_ALIAS) == hr))
            hr = S_OK;

        ExitOnFailure2(hr, "Failed to add user %ls to group '%ls'.", reinterpret_cast<WCHAR*>(bstrUser), reinterpret_cast<WCHAR*>(bstrGroup) );
    }

LExit:
    ReleaseObject(pGroup);
    ReleaseBSTR(bstrUser);
    ReleaseBSTR(bstrGroup);

    return hr;
}

static HRESULT RemoveUserFromGroup(
    __in LPWSTR wzUser,
    __in LPCWSTR wzUserDomain,
    __in LPCWSTR wzGroup,
    __in LPCWSTR wzGroupDomain
    )
{
    Assert(wzUser && *wzUser && wzUserDomain && wzGroup && *wzGroup && wzGroupDomain);

    HRESULT hr = S_OK;
    IADsGroup *pGroup = NULL;
    BSTR bstrUser = NULL;
    BSTR bstrGroup = NULL;
    LPCWSTR wz = NULL;
    LPWSTR pwzUser = NULL;
    LOCALGROUP_MEMBERS_INFO_3 lgmi;

    if (*wzGroupDomain)
    {
        wz = wzGroupDomain;
    }

    // Try removing it from the global group first
    UINT ui = ::NetGroupDelUser(wz, wzGroup, wzUser);
    if (NERR_GroupNotFound == ui)
    {
        // Try removing it from the local group
        if (wzUserDomain)
        {
            hr = StrAllocFormatted(&pwzUser, L"%s\\%s", wzUserDomain, wzUser);
            ExitOnFailure(hr, "failed to allocate user domain string");
        }

        lgmi.lgrmi3_domainandname = (NULL == pwzUser ? wzUser : pwzUser);
        ui = ::NetLocalGroupDelMembers(wz, wzGroup, 3 , reinterpret_cast<LPBYTE>(&lgmi), 1);
    }
    hr = HRESULT_FROM_WIN32(ui);

    //
    // If we failed, try active directory
    //
    if (FAILED(hr))
    {
        WcaLog(LOGMSG_VERBOSE, "Failed to remove user: %ls, domain %ls from group: %ls, domain: %ls with error 0x%x.  Attempting to use Active Directory", wzUser, wzUserDomain, wzGroup, wzGroupDomain, hr);

        hr = UserCreateADsPath(wzUserDomain, wzUser, &bstrUser);
        ExitOnFailure2(hr, "failed to create user ADsPath in order to remove user: %ls domain: %ls from a group", wzUser, wzUserDomain);

        hr = UserCreateADsPath(wzGroupDomain, wzGroup, &bstrGroup);
        ExitOnFailure2(hr, "failed to create group ADsPath in order to remove user from group: %ls domain: %ls", wzGroup, wzGroupDomain);

        hr = ::ADsGetObject(bstrGroup,IID_IADsGroup, reinterpret_cast<void**>(&pGroup));
        ExitOnFailure1(hr, "Failed to get group '%ls'.", reinterpret_cast<WCHAR*>(bstrGroup) );

        hr = pGroup->Remove(bstrUser);
        ExitOnFailure2(hr, "Failed to remove user %ls from group '%ls'.", reinterpret_cast<WCHAR*>(bstrUser), reinterpret_cast<WCHAR*>(bstrGroup) );
    }

LExit:
    ReleaseObject(pGroup);
    ReleaseBSTR(bstrUser);
    ReleaseBSTR(bstrGroup);

    return hr;
}


static HRESULT ModifyUserLocalServiceRight(
    __in_opt LPCWSTR wzDomain,
    __in LPCWSTR wzName,
    __in BOOL fAdd
    )
{
    HRESULT hr = S_OK;
    NTSTATUS nt = 0;

    LPWSTR pwzUser = NULL;
    PSID psid = NULL;
    LSA_HANDLE hPolicy = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    LSA_UNICODE_STRING lucPrivilege = { 0 };

    if (wzDomain && *wzDomain)
    {
        hr = StrAllocFormatted(&pwzUser, L"%s\\%s", wzDomain, wzName);
        ExitOnFailure(hr, "Failed to allocate user with domain string");
    }
    else
    {
        hr = StrAllocString(&pwzUser, wzName, 0);
        ExitOnFailure(hr, "Failed to allocate string from user name.");
    }

    hr = AclGetAccountSid(NULL, pwzUser, &psid);
    ExitOnFailure1(hr, "Failed to get SID for user: %ls", pwzUser);

    nt = ::LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hPolicy);
    hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
    ExitOnFailure(hr, "Failed to open LSA policy store.");

    lucPrivilege.Buffer = L"SeServiceLogonRight";
    lucPrivilege.Length = static_cast<USHORT>(lstrlenW(lucPrivilege.Buffer) * sizeof(WCHAR));
    lucPrivilege.MaximumLength = (lucPrivilege.Length + 1) * sizeof(WCHAR);

    WcaLog(LOGMSG_VERBOSE, "Going to %ls SeServiceLogonRight: user %ls, domain %ls.", fAdd ? L"add" : L"remove", wzName, wzDomain);
    if (fAdd)
    {
        nt = ::LsaAddAccountRights(hPolicy, psid, &lucPrivilege, 1);
        hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
        ExitOnFailure1(hr, "Failed to add 'logon as service' bit to user: %ls", pwzUser);
    }
    else
    {
        nt = ::LsaRemoveAccountRights(hPolicy, psid, FALSE, &lucPrivilege, 1);
        hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
        ExitOnFailure1(hr, "Failed to remove 'logon as service' bit from user: %ls", pwzUser);
    }

LExit:
    if (hPolicy)
    {
        ::LsaClose(hPolicy);
    }

    ReleaseSid(psid);
    ReleaseStr(pwzUser);
    return hr;
}


static HRESULT ModifyUserLocalBatchRight(
  __in_opt LPCWSTR wzDomain,
  __in LPCWSTR wzName,
  __in BOOL fAdd
  )
{
    HRESULT hr = S_OK;
    NTSTATUS nt = 0;

    LPWSTR pwzUser = NULL;
    PSID psid = NULL;
    LSA_HANDLE hPolicy = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    LSA_UNICODE_STRING lucPrivilege = { 0 };

    if (wzDomain && *wzDomain)
    {
        hr = StrAllocFormatted(&pwzUser, L"%s\\%s", wzDomain, wzName);
        ExitOnFailure(hr, "Failed to allocate user with domain string");
    }
    else
    {
        hr = StrAllocString(&pwzUser, wzName, 0);
        ExitOnFailure(hr, "Failed to allocate string from user name.");
    }

    hr = AclGetAccountSid(NULL, pwzUser, &psid);
    ExitOnFailure1(hr, "Failed to get SID for user: %ls", pwzUser);

    nt = ::LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_ALL_ACCESS, &hPolicy);
    hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
    ExitOnFailure(hr, "Failed to open LSA policy store.");

    lucPrivilege.Buffer = L"SeBatchLogonRight";
    lucPrivilege.Length = static_cast<USHORT>(lstrlenW(lucPrivilege.Buffer) * sizeof(WCHAR));
    lucPrivilege.MaximumLength = (lucPrivilege.Length + 1) * sizeof(WCHAR);

    if (fAdd)
    {
        nt = ::LsaAddAccountRights(hPolicy, psid, &lucPrivilege, 1);
        hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
        ExitOnFailure1(hr, "Failed to add 'logon as batch job' bit to user: %ls", pwzUser);
    }
    else
    {
        nt = ::LsaRemoveAccountRights(hPolicy, psid, FALSE, &lucPrivilege, 1);
        hr = HRESULT_FROM_WIN32(::LsaNtStatusToWinError(nt));
        ExitOnFailure1(hr, "Failed to remove 'logon as batch job' bit from user: %ls", pwzUser);
    }

  LExit:
    if (hPolicy)
    {
        ::LsaClose(hPolicy);
    }

    ReleaseSid(psid);
    ReleaseStr(pwzUser);
    return hr;
}

static void SetUserPasswordAndAttributes(
    __in USER_INFO_1* puserInfo,
    __in LPWSTR wzPassword,
    __in int iAttributes
    )
{
    Assert(puserInfo);

    // Set the User's password
    puserInfo->usri1_password = wzPassword;

    // Apply the Attributes
    if (SCAU_DONT_EXPIRE_PASSWRD & iAttributes)
    {
        puserInfo->usri1_flags |= UF_DONT_EXPIRE_PASSWD;
    }
    else
    {
        puserInfo->usri1_flags &= ~UF_DONT_EXPIRE_PASSWD;
    }

    if (SCAU_PASSWD_CANT_CHANGE & iAttributes)
    {
        puserInfo->usri1_flags |= UF_PASSWD_CANT_CHANGE;
    }
    else
    {
        puserInfo->usri1_flags &= ~UF_PASSWD_CANT_CHANGE;
    }

    if (SCAU_DISABLE_ACCOUNT & iAttributes)
    {
        puserInfo->usri1_flags |= UF_ACCOUNTDISABLE;
    }
    else
    {
        puserInfo->usri1_flags &= ~UF_ACCOUNTDISABLE;
    }

    if (SCAU_PASSWD_CHANGE_REQD_ON_LOGIN & iAttributes) // TODO: for some reason this doesn't work
    {
        puserInfo->usri1_flags |= UF_PASSWORD_EXPIRED;
    }
    else
    {
        puserInfo->usri1_flags &= ~UF_PASSWORD_EXPIRED;
    }
}


/********************************************************************
 CreateUser - CUSTOM ACTION ENTRY POINT for creating users

  Input:  deferred CustomActionData - UserName\tDomain\tPassword\tAttributes\tGroupName\tDomain\tGroupName\tDomain...
 * *****************************************************************/
extern "C" UINT __stdcall CreateUser(
    __in MSIHANDLE hInstall
    )
{
    //AssertSz(0, "Debug CreateUser");

    HRESULT hr = S_OK;
    UINT er = ERROR_SUCCESS;

    LPWSTR pwzData = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzName = NULL;
    LPWSTR pwzDomain = NULL;
    LPWSTR pwzPassword = NULL;
    LPWSTR pwzGroup = NULL;
    LPWSTR pwzGroupDomain = NULL;
    PDOMAIN_CONTROLLER_INFOW pDomainControllerInfo = NULL;
    int iAttributes = 0;
    BOOL fInitializedCom = FALSE;

    USER_INFO_1 userInfo;
    USER_INFO_1* puserInfo = NULL;
    DWORD dw;
    LPCWSTR wz = NULL;

    hr = WcaInitialize(hInstall, "CreateUser");
    ExitOnFailure(hr, "failed to initialize");

    hr = ::CoInitialize(NULL);
    ExitOnFailure(hr, "failed to initialize COM");
    fInitializedCom = TRUE;

    hr = WcaGetProperty( L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    WcaLog(LOGMSG_TRACEONLY, "CustomActionData: %ls", pwzData);

    //
    // Read in the CustomActionData
    //
    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &pwzName);
    ExitOnFailure(hr, "failed to read user name from custom action data");

    hr = WcaReadStringFromCaData(&pwz, &pwzDomain);
    ExitOnFailure(hr, "failed to read domain from custom action data");

    hr = WcaReadIntegerFromCaData(&pwz, &iAttributes);
    ExitOnFailure(hr, "failed to read attributes from custom action data");

    hr = WcaReadStringFromCaData(&pwz, &pwzPassword);
    ExitOnFailure(hr, "failed to read password from custom action data");

    if (!(SCAU_DONT_CREATE_USER & iAttributes))
    {
        ::ZeroMemory(&userInfo, sizeof(USER_INFO_1));
        userInfo.usri1_name = pwzName;
        userInfo.usri1_priv = USER_PRIV_USER;
        userInfo.usri1_flags = UF_SCRIPT;
        userInfo.usri1_home_dir = NULL;
        userInfo.usri1_comment = NULL;
        userInfo.usri1_script_path = NULL;

        SetUserPasswordAndAttributes(&userInfo, pwzPassword, iAttributes);

        //
        // Create the User
        //
        if (pwzDomain && *pwzDomain)
        {
            er = ::DsGetDcNameW( NULL, (LPCWSTR)pwzDomain, NULL, NULL, NULL, &pDomainControllerInfo );
            if (RPC_S_SERVER_UNAVAILABLE == er)
            {
                // MSDN says, if we get the above error code, try again with the "DS_FORCE_REDISCOVERY" flag
                er = ::DsGetDcNameW( NULL, (LPCWSTR)pwzDomain, NULL, NULL, DS_FORCE_REDISCOVERY, &pDomainControllerInfo );
            }
            if (ERROR_SUCCESS == er)
            {
                wz = pDomainControllerInfo->DomainControllerName + 2;  //Add 2 so that we don't get the \\ prefix
                WcaLog(LOGMSG_VERBOSE, "Using domain controller: %ls", wz);
            }
            else
            {
                wz = pwzDomain;
                WcaLog(LOGMSG_VERBOSE, "Using machine: %ls", wz);
            }
        }

        er = ::NetUserAdd(wz, 1, reinterpret_cast<LPBYTE>(&userInfo), &dw);
        WcaLog(LOGMSG_VERBOSE, "NetUserAdd returned %d/%d.", er, dw);
        if (NERR_UserExists == er)
        {
            if (SCAU_UPDATE_IF_EXISTS & iAttributes)
            {
                er = ::NetUserGetInfo(wz, pwzName, 1, reinterpret_cast<LPBYTE*>(&puserInfo));
                WcaLog(LOGMSG_VERBOSE, "NetUserGetInfo returned %d.", er);
                if (NERR_Success == er)
                {
                    // Change the existing user's password and attributes again then try
                    // to update user with this new data
                    SetUserPasswordAndAttributes(puserInfo, pwzPassword, iAttributes);

                    er = ::NetUserSetInfo(wz, pwzName, 1, reinterpret_cast<LPBYTE>(puserInfo), &dw);
                    WcaLog(LOGMSG_VERBOSE, "NetUserSetInfo returned %d.", er);
                }
            }
            else if (!(SCAU_FAIL_IF_EXISTS & iAttributes))
            {
                er = NERR_Success;
                WcaLog(LOGMSG_VERBOSE, "User exists and FailIfExists is not set.");
            }
        }
        else if (NERR_PasswordTooShort == er || NERR_PasswordTooLong == er)
        {
            WcaLog(LOGMSG_VERBOSE, "Bad password, code %d.", er);
            MessageExitOnFailure1(hr = HRESULT_FROM_WIN32(er), msierrUSRFailedUserCreatePswd, "failed to create user: %ls due to invalid password.", pwzName);
        }
        MessageExitOnFailure1(hr = HRESULT_FROM_WIN32(er), msierrUSRFailedUserCreate, "failed to create user: %ls", pwzName);
    }

    if (SCAU_ALLOW_LOGON_AS_SERVICE & iAttributes)
    {
        WcaLog(LOGMSG_VERBOSE, "Adding logon-as-service.");
        hr = ModifyUserLocalServiceRight(pwzDomain, pwzName, TRUE);
        MessageExitOnFailure1(hr, msierrUSRFailedGrantLogonAsService, "Failed to grant logon as service rights to user: %ls", pwzName);
    }

    if (SCAU_ALLOW_LOGON_AS_BATCH & iAttributes)
    {
        WcaLog(LOGMSG_VERBOSE, "Adding logon-as-batch.");
        hr = ModifyUserLocalBatchRight(pwzDomain, pwzName, TRUE);
        MessageExitOnFailure1(hr, msierrUSRFailedGrantLogonAsService, "Failed to grant logon as batch job rights to user: %ls", pwzName);
    }

    //
    // Add the users to groups
    //
    while (S_OK == (hr = WcaReadStringFromCaData(&pwz, &pwzGroup)))
    {
        hr = WcaReadStringFromCaData(&pwz, &pwzGroupDomain);
        ExitOnFailure1(hr, "failed to get domain for group: %ls", pwzGroup);

        hr = AddUserToGroup(pwzName, pwzDomain, pwzGroup, pwzGroupDomain);
        MessageExitOnFailure2(hr, msierrUSRFailedUserGroupAdd, "failed to add user: %ls to group %ls", pwzName, pwzGroup);
    }
    if (E_NOMOREITEMS == hr) // if there are no more items, all is well
    {
        hr = S_OK;
    }
    ExitOnFailure1(hr, "failed to get next group in which to include user:%ls", pwzName);

LExit:
    if (puserInfo)
    {
        ::NetApiBufferFree((LPVOID)puserInfo);
    }

    if (pDomainControllerInfo)
    {
        ::NetApiBufferFree((LPVOID)pDomainControllerInfo);
    }

    ReleaseStr(pwzData);
    ReleaseStr(pwzName);
    ReleaseStr(pwzDomain);
    ReleaseStr(pwzPassword);
    ReleaseStr(pwzGroup);
    ReleaseStr(pwzGroupDomain);

    if (fInitializedCom)
    {
        ::CoUninitialize();
    }

    if (SCAU_NON_VITAL & iAttributes)
    {
        er = ERROR_SUCCESS;
    }
    else if (FAILED(hr))
    {
        er = ERROR_INSTALL_FAILURE;
    }

    return WcaFinalize(er);
}


/********************************************************************
 RemoveUser - CUSTOM ACTION ENTRY POINT for removing users

  Input:  deferred CustomActionData - Name\tDomain
 * *****************************************************************/
extern "C" UINT __stdcall RemoveUser(
    MSIHANDLE hInstall
    )
{
    //AssertSz(0, "Debug RemoveAccount");

    HRESULT hr = S_OK;
    UINT er = ERROR_SUCCESS;

    LPWSTR pwzData = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzName = NULL;
    LPWSTR pwzDomain= NULL;
    LPWSTR pwzGroup = NULL;
    LPWSTR pwzGroupDomain = NULL;
    int iAttributes = 0;
    LPCWSTR wz = NULL;
    PDOMAIN_CONTROLLER_INFOW pDomainControllerInfo = NULL;
    BOOL fInitializedCom = FALSE;

    hr = WcaInitialize(hInstall, "RemoveUser");
    ExitOnFailure(hr, "failed to initialize");

    hr = ::CoInitialize(NULL);
    ExitOnFailure(hr, "failed to initialize COM");
    fInitializedCom = TRUE;

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    WcaLog(LOGMSG_TRACEONLY, "CustomActionData: %ls", pwzData);

    //
    // Read in the CustomActionData
    //
    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &pwzName);
    ExitOnFailure(hr, "failed to read name from custom action data");

    hr = WcaReadStringFromCaData(&pwz, &pwzDomain);
    ExitOnFailure(hr, "failed to read domain from custom action data");

    hr = WcaReadIntegerFromCaData(&pwz, &iAttributes);
    ExitOnFailure(hr, "failed to read attributes from custom action data");

    //
    // Remove the logon as service privilege.
    //
    if (SCAU_ALLOW_LOGON_AS_SERVICE & iAttributes)
    {
        hr = ModifyUserLocalServiceRight(pwzDomain, pwzName, FALSE);
        if (FAILED(hr))
        {
            WcaLogError(hr, "Failed to remove logon as service right from user, continuing...");
            hr = S_OK;
        }
    }

    if (SCAU_ALLOW_LOGON_AS_BATCH & iAttributes)
    {
        hr = ModifyUserLocalBatchRight(pwzDomain, pwzName, FALSE);
        if (FAILED(hr))
        {
            WcaLogError(hr, "Failed to remove logon as batch job right from user, continuing...");
            hr = S_OK;
        }
    }

    //
    // Remove the User Account if the user was created by us.
    //
    if (!(SCAU_DONT_CREATE_USER & iAttributes))
    {
        if (pwzDomain && *pwzDomain)
        {
            er = ::DsGetDcNameW( NULL, (LPCWSTR)pwzDomain, NULL, NULL, NULL, &pDomainControllerInfo );
            if (HRESULT_FROM_WIN32(er) == RPC_S_SERVER_UNAVAILABLE)
            {
                // MSDN says, if we get the above error code, try again with the "DS_FORCE_REDISCOVERY" flag
                er = ::DsGetDcNameW( NULL, (LPCWSTR)pwzDomain, NULL, NULL, DS_FORCE_REDISCOVERY, &pDomainControllerInfo );
            }
            if (ERROR_SUCCESS == er)
            {
                wz = pDomainControllerInfo->DomainControllerName + 2;  //Add 2 so that we don't get the \\ prefix
            }
            else
            {
                wz = pwzDomain;
            }
        }

        er = ::NetUserDel(wz, pwzName);
        if (NERR_UserNotFound == er)
        {
            er = NERR_Success;
        }
        ExitOnFailure1(hr = HRESULT_FROM_WIN32(er), "failed to delete user account: %ls", pwzName);
    }
    else
    {
        //
        // Remove the user from the groups
        //
        while (S_OK == (hr = WcaReadStringFromCaData(&pwz, &pwzGroup)))
        {
            hr = WcaReadStringFromCaData(&pwz, &pwzGroupDomain);

            if (FAILED(hr))
            {
                WcaLogError(hr, "failed to get domain for group: %ls, continuing anyway.", pwzGroup);
            }
            else
            {
                hr = RemoveUserFromGroup(pwzName, pwzDomain, pwzGroup, pwzGroupDomain);
                if (FAILED(hr))
                {
                    WcaLogError(hr, "failed to remove user: %ls from group %ls, continuing anyway.", pwzName, pwzGroup);
                }
            }
        }

        if (E_NOMOREITEMS == hr) // if there are no more items, all is well
        {
            hr = S_OK;
        }

        ExitOnFailure1(hr, "failed to get next group from which to remove user:%ls", pwzName);
    }

LExit:
    if (pDomainControllerInfo)
    {
        ::NetApiBufferFree(static_cast<LPVOID>(pDomainControllerInfo));
    }

    ReleaseStr(pwzData);
    ReleaseStr(pwzName);
    ReleaseStr(pwzDomain);

    if (fInitializedCom)
    {
        ::CoUninitialize();
    }

    if (FAILED(hr))
    {
        er = ERROR_INSTALL_FAILURE;
    }

    return WcaFinalize(er);
}
