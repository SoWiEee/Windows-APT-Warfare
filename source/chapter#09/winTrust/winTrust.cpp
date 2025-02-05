﻿//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Example of verifying the embedded signature of a PE file by using 
// the WinVerifyTrust function.

#define _UNICODE 1
#define UNICODE 1

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

// 驗證數位簽章
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    LONG lStatus;
    DWORD dwLastError;

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;    // 將 pcwszFilePath 欄位指向受驗證檔案的路徑
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root certificate
    located in the trusted root certificate store. This implies that the identity of
    the publisher has been verified by a certification authority.

    2) In cases where user interface is displayed (which this example does not do),
       WinVerifyTrust will check for whether the end entity certificate is stored
       in the trusted publisher store, implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign code,
       as indicated by the presence of a code signing EKU or no EKU.
    */
    // 被驗證的檔案室受到 Authenticode 規格簽署的數位簽章後的檔案
    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.
    // 儲存後續呼叫 WinVerifyTrust 進行驗證時的參數
    memset(&WinTrustData, 0, sizeof(WinTrustData));       // Default all fields to 0.
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;              // Use default code signing EKU.
    WinTrustData.pSIPClientData = NULL;                   // No data to pass to SIP.
    WinTrustData.dwUIChoice = WTD_UI_NONE;                // Disable WVT UI.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;   // No revocation checking.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;         // Verify an embedded signature on a file.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;  // Verify action.
    WinTrustData.hWVTStateData = NULL;                    // Verification sets this value.
    WinTrustData.pwszURLReference = NULL;                 // Not used.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    // 
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID and Wintrust_Data.
    // 驗證採用的 COM Interface(GUID) 與 WINTRUST_DATA，並取得回傳值 
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);
    /*
        (1) CryptSIPDllIsMyFileType: 依序確認傳入檔案是否為 PE/Catalog/CTL/Cabinet，並回傳對應 SIP 接口的 GUID 序號
        (2) CryptSIPGetSignedDataMsg: 以對應 SIP 接口從當前檔案提取簽名資訊
        (3) CryptSIPVetifyIndirectData: 計算當前檔案的 hash 結果當作指紋，並與簽名資訊比對
    */
    switch (lStatus){
    // 傳入檔案的數位簽章驗證通過，且檔案無損毀或遭竄改的疑慮
    case ERROR_SUCCESS:
        /*
        Signed file:
            - Hash that represents the subject is trusted.

            - Trusted publisher without any verification errors.

            - UI was disabled in dwUIChoice. No publisher or
                time stamp chain errors.

            - UI was enabled in dwUIChoice and the user clicked
                "Yes" when asked to install and run the signed
                subject.
        */
        wprintf_s(L"The file \"%s\" is signed and the signature "
            L"was verified.\n",
            pwszSourceFile);
        break;
    // 傳入檔案的簽名內容不存在或其數位簽章無效
    case TRUST_E_NOSIGNATURE:
        // The file was not signed or had a signature 
        // that was not valid.

        // Get the reason for no signature.
        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            // The file was not signed.
            wprintf_s(L"The file \"%s\" is not signed.\n",
                pwszSourceFile);
        }
        else
        {
            // The signature was not valid or there was an error 
            // opening the file.
            wprintf_s(L"An unknown error occurred trying to "
                L"verify the signature of the \"%s\" file.\n",
                pwszSourceFile);
        }
        break;
    // 傳入檔案的數位簽章驗證通過，但該簽名效力被簽署人或當前用戶禁用從而無效
    case TRUST_E_EXPLICIT_DISTRUST:
        // The hash that represents the subject or the publisher 
        // is not allowed by the admin or user.
        wprintf_s(L"The signature is present, but specifically "
            L"disallowed.\n");
        break;
    // 該安裝該簽名之證書到本地系統時，被用戶手動阻止，導致此簽名不被信任
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // The user clicked "No" when asked to install and run.
        wprintf_s(L"The signature is present, but not "
            L"trusted.\n");
        break;
    // 該簽名證書當前被網管設下的群組原則禁用、指紋計算結果不吻合當前傳入檔案、時間戳記異常等
    case CRYPT_E_SECURITY_SETTINGS:
        /*
        The hash that represents the subject or the publisher
        was not explicitly trusted by the admin and the
        admin policy has disabled user trust. No signature,
        publisher or time stamp errors.
        */
        wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
            L"representing the subject or the publisher wasn't "
            L"explicitly trusted by the admin and admin policy "
            L"has disabled user trust. No signature, publisher "
            L"or timestamp errors.\n");
        break;

    default:
        // The UI was disabled in dwUIChoice or the admin policy 
        // has disabled user trust. lStatus contains the 
        // publisher or time stamp chain error.
        wprintf_s(L"Error is: 0x%x.\n",
            lStatus);
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
    if (argc > 1)
    {
        // 讀入程式檔案，並進行校驗數位簽章，最後輸出結果
        VerifyEmbeddedSignature(argv[1]);
    }

    return 0;
}


