// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

#include "precomp.h"

const int ConfigureIIsCost = 8;
const int WriteMetabaseChangesCost = 20;
const int WriteIIS7ConfigChangesCost = 20;

// sql queries
LPCWSTR vcsUserDeferredQuery = L"SELECT `User`, `Component_`, `Name`, `Domain`, `Password` FROM `User`";

LPCWSTR vcsWebSvcExtQuery = L"SELECT `Component_`, `File`, `Description`, `Group`, `Attributes` FROM `IIsWebServiceExtension`";

LPCWSTR vcsAppPoolQuery = L"SELECT `AppPool`, `Name`, `Component_`, `Attributes`, `User_`, `RecycleMinutes`, `RecycleRequests`, `RecycleTimes`, `VirtualMemory`, `PrivateMemory`, `IdleTimeout`, `QueueLimit`, `CPUMon`, `MaxProc`, `ManagedRuntimeVersion`, `ManagedPipelineMode` FROM `IIsAppPool`";

LPCWSTR vcsComponentAttrQuery = L"SELECT `Component`,`Attributes` FROM `Component`";

LPCWSTR vcsMimeMapQuery = L"SELECT `MimeMap`, `ParentType`, `ParentValue`, `MimeType`, `Extension` FROM `IIsMimeMap`";

LPCWSTR vcsHttpHeaderQuery = L"SELECT `Name`, `ParentType`, `ParentValue`, `Value`, `Attributes` FROM `IIsHttpHeader` ORDER BY `Sequence`";

LPCWSTR vcsWebErrorQuery =
    L"SELECT `ErrorCode`, `SubCode`, `ParentType`, `ParentValue`, `File`, `URL` "
    L"FROM `IIsWebError` ORDER BY `ErrorCode`, `SubCode`";

LPCWSTR vcsWebDirPropertiesQuery = L"SELECT `DirProperties`, `Access`, `Authorization`, `AnonymousUser_`, `IIsControlledPassword`, `LogVisits`, `Index`, `DefaultDoc`, `AspDetailedError`, `HttpExpires`, `CacheControlMaxAge`, `CacheControlCustom`, `NoCustomError`, `AccessSSLFlags`, `AuthenticationProviders` "
    L"FROM `IIsWebDirProperties`";

LPCWSTR vcsSslCertificateQuery = L"SELECT `Certificate`.`StoreName`, `CertificateHash`.`Hash`, `IIsWebSiteCertificates`.`Web_` FROM `Certificate`, `CertificateHash`, `IIsWebSiteCertificates` WHERE `Certificate`.`Certificate`=`CertificateHash`.`Certificate_` AND `CertificateHash`.`Certificate_`=`IIsWebSiteCertificates`.`Certificate_`";

LPCWSTR vcsWebLogQuery = L"SELECT `Log`, `Format` "
    L"FROM `IIsWebLog`";

LPCWSTR vcsWebApplicationQuery = L"SELECT `Name`, `Isolation`, `AllowSessions`, `SessionTimeout`, "
    L"`Buffer`, `ParentPaths`, `DefaultScript`, `ScriptTimeout`, "
    L"`ServerDebugging`, `ClientDebugging`, `AppPool_`, `Application` "
    L"FROM `IIsWebApplication`";

LPCWSTR vcsWebAppExtensionQuery = L"SELECT `Extension`, `Verbs`, `Executable`, `Attributes`, `Application_` FROM `IIsWebApplicationExtension`";

LPCWSTR vcsWebQuery = L"SELECT `Web`, `Component_`, `Id`, `Description`, `ConnectionTimeout`, `Directory_`, `State`, `Attributes`, `DirProperties_`, `Application_`, "
    L"`Address`, `IP`, `Port`, `Header`, `Secure`, `Log_` FROM `IIsWebSite`, `IIsWebAddress` "
    L"WHERE `KeyAddress_`=`Address` ORDER BY `Sequence`";

LPCWSTR vcsWebAddressQuery = L"SELECT `Address`, `Web_`, `IP`, `Port`, `Header`, `Secure` "
    L"FROM `IIsWebAddress`";

LPCWSTR vcsWebBaseQuery = L"SELECT `Web`, `Id`, `IP`, `Port`, `Header`, `Secure`, `Description` "
    L"FROM `IIsWebSite`, `IIsWebAddress` "
    L"WHERE `KeyAddress_`=`Address`";

LPCWSTR vcsWebDirQuery = L"SELECT `Web_`, `WebDir`, `Component_`, `Path`, `DirProperties_`, `Application_` "
    L"FROM `IIsWebDir`";

LPCWSTR vcsVDirQuery = L"SELECT `Web_`, `VirtualDir`, `Component_`, `Alias`, `Directory_`, `DirProperties_`, `Application_` "
    L"FROM `IIsWebVirtualDir`";

LPCWSTR vcsFilterQuery = L"SELECT `Web_`, `Name`, `Component_`, `Path`, `Description`, `Flags`, `LoadOrder` FROM `IIsFilter` ORDER BY `Web_`";

LPCWSTR vcsPropertyQuery = L"SELECT `Property`, `Component_`, `Attributes`, `Value` "
    L"FROM `IIsProperty`";

#define IIS7CONDITION L"VersionNT >= 600"
#define USEIIS7CONDITION IIS7CONDITION L"AND NOT UseIis6Compatibility"

/********************************************************************
ConfigureUsers - CUSTOM ACTION ENTRY POINT for installing users

********************************************************************/
extern "C" UINT __stdcall ConfigureUsers(
    __in MSIHANDLE hInstall
    )
{
    //AssertSz(0, "Debug ConfigureUsers");

    HRESULT hr = S_OK;
    UINT er = ERROR_SUCCESS;

    BOOL fInitializedCom = FALSE;
    SCA_USER* psuList = NULL;

    // initialize
    hr = WcaInitialize(hInstall, "ConfigureUsers");
    ExitOnFailure(hr, "Failed to initialize");

    hr = ::CoInitialize(NULL);
    ExitOnFailure(hr, "failed to initialize COM");
    fInitializedCom = TRUE;

    hr = ScaUserRead(&psuList);
    ExitOnFailure(hr, "failed to read User table");

    hr = ScaUserExecute(psuList);
    ExitOnFailure(hr, "failed to add/remove User actions");

LExit:
    if (psuList)
    {
        ScaUserFreeList(psuList);
    }

    if (fInitializedCom)
    {
        ::CoUninitialize();
    }

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}
