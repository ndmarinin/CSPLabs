#pragma once

#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>

void Task1();
LPTSTR Task2(DWORD type);
HCRYPTPROV Task3(LPTSTR pszName, DWORD type);
void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);
void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer);
void printNamesContFromProv(HCRYPTPROV hCryptProv);
int getUserInput(std::string prompt);
PROV_ENUMALGS parse(BYTE* data);
void printInfo(PROV_ENUMALGS info);

void Task1() {
    std::cout << "\n-----Task 1-----" << std::endl;
    printf("Listing Available Provider Types:\n");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;

    while (CryptEnumProviderTypes(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        if (!cbName) break;

        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return;

        if (!CryptEnumProviderTypes(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) {
            std::cout << "CryptEnumProvidersTypes" << std::endl;
            return;
        }

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());

        std::cout << "--------------------------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }
}

LPTSTR Task2(DWORD type) {
    std::cout << "\n-----Task 2-----" << std::endl;
    printf("Listing Available Providers:\n");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPTSTR pszName;
    LPTSTR pszNameOut;

    int i = 1;
    std::vector<LPTSTR> listNamesProviders;

    while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        if (dwType != type) {
            ++dwIndex;
            continue;
        }

        if (!cbName) break;

        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;
        if (!(pszNameOut = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) return NULL;

        if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) {
            std::cout << "CryptEnumProviders" << std::endl;
            return NULL;
        }

        lstrcpy(pszNameOut, pszName);

        std::wstring pszNameWSTR(pszName);
        std::string pszNameStr(pszNameWSTR.begin(), pszNameWSTR.end());
        listNamesProviders.push_back(pszNameOut);

        std::cout << "----------------" << i++ << "----------------" << std::endl;
        std::cout << "Provider name: " << pszNameStr << std::endl;
        std::cout << "Provider type: " << dwType << std::endl;
        LocalFree(pszName);
    }

    i = getUserInput("Choose provider name: ");

    for (int a = 0; a < listNamesProviders.size(); a++) {
        if (i - 1 == a) {
            continue;
        }
        LocalFree(listNamesProviders[a]);
    }

    return listNamesProviders[i - 1];
}

HCRYPTPROV Task3(LPTSTR pszName, DWORD type) {
    HCRYPTPROV hCryptProv;
    BYTE pbData[1000];

    if (CryptAcquireContext(&hCryptProv, NULL, pszName, type, 0)) {
        printf("Context has been obtained\n");
    }
    else {
        if (CryptAcquireContext(&hCryptProv, NULL, pszName, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            printf("A new key container has been created.\n");
        }
        else {
            printf("Could not create a new key container.\n");
            exit(1);
        }
    }

    DWORD cbData;

    cbData = 1000;

    if (CryptGetProvParam(hCryptProv, PP_NAME, pbData, &cbData, 0)) {
        printf("Provider name: %s\n", pbData);
    }
    else {
        printf("Error reading CSP name.\n");
        exit(1);
    }

    cbData = 1000;

    if (CryptGetProvParam(hCryptProv, PP_UNIQUE_CONTAINER, pbData, &cbData, 0)) {
        printf("Unique name of container: %s\n", pbData);
    }
    else {
        printf("Error reading CSP admin pin.\n");
        exit(1);
    }

    cbData = 1000;

    if (CryptGetProvParam(hCryptProv, PP_ENUMALGS, pbData, &cbData, CRYPT_FIRST)) {
        PROV_ENUMALGS info_algo = parse(pbData);
        printInfo(info_algo);
    }
    else {
        printf("Error reading CSP admin pin.\n");
        exit(1);
    }

    while (CryptGetProvParam(hCryptProv, PP_ENUMALGS, pbData, &cbData, CRYPT_NEXT)) {
        PROV_ENUMALGS info_algo = parse(pbData);
        printInfo(info_algo);
    }

    return hCryptProv;
}

void Task4(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {
    LPSTR pszUserName;
    DWORD dwUserNameLen;

    if (CryptAcquireContext(&hCryptProv, nameContainer, pszNameProv, type, CRYPT_NEWKEYSET)) {
        printf("A new key container has been created.\n");
    }
    else {
        printf("Could not create a new key container.\n");
        return;
    }

    if (!CryptGetProvParam(hCryptProv, PP_CONTAINER, NULL, &dwUserNameLen, 0)) {
        printf("Error: %d", GetLastError());
        exit(1);
    }

    pszUserName = (char*)malloc((dwUserNameLen + 1));

    if (!CryptGetProvParam(hCryptProv, PP_CONTAINER, (LPBYTE)pszUserName, &dwUserNameLen, 0)) {
        free(pszUserName);
        printf("error occurred getting the key container name. Error: %d", GetLastError());
        exit(1);
    }
    else {
        printf("A crypto context has been acquired and \n");
        printf("The name on the key container is %s\n\n", pszUserName);
        free(pszUserName);
    }

    HCRYPTKEY hKey = 0;

    if (CryptGetUserKey(hCryptProv, AT_SIGNATURE, &hKey)) {
        printf("A signature key is available.\n");
    }
    else {
        printf("No signature key is available.\n");

        if (!(GetLastError() == (DWORD)NTE_NO_KEY)) {
            printf("An error other than NTE_NO_KEY getting signature key.\n");
            exit(1);
        }

        printf("The signature key does not exist.\n");
        printf("Creating a signature key pair...\n");

        if (!CryptGenKey(hCryptProv, AT_SIGNATURE, 0, &hKey)) {
            printf("Error occurred creating a signature key.\n");
            exit(1);
        }
        printf("Created a signature key pair.\n");
    }

    if (CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hKey)) {
        printf("An exchange key exists. \n");
    }
    else {
        printf("No exchange key is available.\n");
    }

    printf("Everything is okay. A signature key\n");
    printf("pair and an exchange key exist in\n");
    wprintf(L"the %s key container.\n", nameContainer);
}

void Task5(HCRYPTPROV hCryptProv, LPTSTR pszNameProv, DWORD type, LPCWSTR nameContainer) {
    if (CryptAcquireContext(&hCryptProv, nameContainer, pszNameProv, type, CRYPT_DELETEKEYSET)) {
        wprintf(L"A existing key container {%s} has been deleted.\n", nameContainer);
    }
    else {
        printf("Could not delete an existing key container.\n");
        exit(1);
    }
}

void printNamesContFromProv(HCRYPTPROV hCryptProv) {
    DWORD dwFlags = CRYPT_FIRST;
    DWORD cbData = 1000;

    CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, NULL, &cbData, dwFlags);

    PBYTE pbData = new BYTE[cbData];

    if (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, pbData, &cbData, dwFlags)) {
        printf("Name container: %s\n", pbData);
    }
    else {
        printf("Error %d\n", GetLastError());
        printf("Error reading CSP name. \n");
    }

    cbData = 1000;

    while (CryptGetProvParam(hCryptProv, PP_ENUMCONTAINERS, pbData, &cbData, CRYPT_NEXT)) {
        printf("Name container next: %s\n", pbData);
    }
}

int getUserInput(std::string prompt) {
    std::cout << prompt;
    int type = 1;
    std::cin >> type;
    return type;
}

PROV_ENUMALGS parse(BYTE* data) {
    PROV_ENUMALGS out;
    ALG_ID id;
    id = *(ALG_ID*)data;
    BYTE* ptr = &data[0];

    ptr += sizeof(ALG_ID);

    out.aiAlgid = id;
    out.dwBitLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);
    out.dwNameLen = *(DWORD*)ptr;
    ptr += sizeof(DWORD);

    strncpy_s(out.szName, sizeof(out.szName), (char*)ptr, out.dwNameLen);

    return out;
}

void printInfo(PROV_ENUMALGS info) {
    printf("---------------------\n");
    printf("algo_id: %d\nlen key: %d\nlen name: %d\nname algo: %s\n",
        info.aiAlgid, info.dwBitLen, info.dwNameLen, info.szName);
    printf("---------------------\n");
}
