#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int parse_ipv4(const char *s, uint32_t *out) {
    // Acepta "a.b.c.d" (0..255)
    unsigned a, b, c, d;
    char tail;
    if (sscanf(s, " %u.%u.%u.%u %c", &a, &b, &c, &d, &tail) < 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 1;
}

static void ipv4_to_str(uint32_t ip, char *buf, size_t n) {
    snprintf(buf, n, "%u.%u.%u.%u",
             (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

static uint32_t prefix_to_mask(int prefix) {
    if (prefix <= 0) return 0u;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

static int parse_cidr(const char *s, uint32_t *ip, int *prefix) {
    // Acepta "a.b.c.d/p"
    char ip_part[64];
    int p;
    const char *slash = strchr(s, '/');
    if (!slash) return 0;

    size_t len = (size_t)(slash - s);
    if (len >= sizeof(ip_part)) return 0;
    memcpy(ip_part, s, len);
    ip_part[len] = '\0';

    if (!parse_ipv4(ip_part, ip)) return 0;

    if (sscanf(slash + 1, " %d", &p) != 1) return 0;
    if (p < 0 || p > 32) return 0;

    *prefix = p;
    return 1;
}

static const char* ip_class(uint32_t ip) {
    unsigned first = (ip >> 24) & 255;
    if (first <= 127) return "A";
    if (first <= 191) return "B";
    if (first <= 223) return "C";
    if (first <= 239) return "D (Multicast)";
    return "E (Reservada)";
}

static int is_private(uint32_t ip) {
    unsigned a = (ip >> 24) & 255;
    unsigned b = (ip >> 16) & 255;

    // 10.0.0.0/8
    if (a == 10) return 1;
    // 172.16.0.0/12  -> 172.16..172.31
    if (a == 172 && (b >= 16 && b <= 31)) return 1;
    // 192.168.0.0/16
    if (a == 192 && b == 168) return 1;

    return 0;
}

static void print_subnet_info(uint32_t ip, int prefix) {
    uint32_t mask = prefix_to_mask(prefix);
    uint32_t wildcard = ~mask;
    uint32_t network = ip & mask;
    uint32_t broadcast = network | wildcard;

    char ip_s[32], mask_s[32], wc_s[32], net_s[32], bc_s[32];
    ipv4_to_str(ip, ip_s, sizeof(ip_s));
    ipv4_to_str(mask, mask_s, sizeof(mask_s));
    ipv4_to_str(wildcard, wc_s, sizeof(wc_s));
    ipv4_to_str(network, net_s, sizeof(net_s));
    ipv4_to_str(broadcast, bc_s, sizeof(bc_s));

    printf("\n=== Resultados ===\n");
    printf("IP:               %s\n", ip_s);
    printf("Prefijo:          /%d\n", prefix);
    printf("Mascara:          %s\n", mask_s);
    printf("Wildcard:         %s\n", wc_s);
    printf("Clase (por 1er octeto): %s\n", ip_class(ip));
    printf("Privada:          %s\n", is_private(ip) ? "SI" : "NO");
    printf("Red (Network):    %s\n", net_s);
    printf("Broadcast:        %s\n", bc_s);

    // Hosts disponibles (ojo con /31 y /32)
    if (prefix == 32) {
        printf("Hosts utilizables: 1 (solo esa IP)\n");
        printf("Host (unico):      %s\n", ip_s);
    } else if (prefix == 31) {
        // RFC 3021: /31 se usa para enlaces punto-a-punto (2 IPs, sin broadcast tradicional)
        printf("Hosts utilizables: 2 (enlace punto-a-punto /31)\n");
        char h1[32], h2[32];
        ipv4_to_str(network, h1, sizeof(h1));
        ipv4_to_str(broadcast, h2, sizeof(h2));
        printf("IPs del /31:       %s  y  %s\n", h1, h2);
    } else {
        uint32_t first_host = network + 1;
        uint32_t last_host  = broadcast - 1;

        uint64_t total_ips = 1ULL << (32 - prefix);
        uint64_t usable = (total_ips >= 2) ? (total_ips - 2) : 0;

        char fh_s[32], lh_s[32];
        ipv4_to_str(first_host, fh_s, sizeof(fh_s));
        ipv4_to_str(last_host, lh_s, sizeof(lh_s));

        printf("Total de IPs:      %llu\n", (unsigned long long)total_ips);
        printf("Hosts utilizables: %llu\n", (unsigned long long)usable);
        printf("Primer host:       %s\n", fh_s);
        printf("Ultimo host:       %s\n", lh_s);
    }
    printf("==================\n\n");
}

static void clear_line(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

int main(void) {
    for (;;) {
        printf("Calculadora IPv4 Subnet\n");
        printf("1) Ingresar CIDR (ej. 192.168.1.37/26)\n");
        printf("2) Ingresar IP + prefijo por separado\n");
        printf("0) Salir\n");
        printf("Opcion: ");

        int op;
        if (scanf("%d", &op) != 1) break;
        clear_line();

        if (op == 0) break;

        uint32_t ip;
        int prefix;

        if (op == 1) {
            char line[128];
            printf("CIDR: ");
            if (!fgets(line, sizeof(line), stdin)) break;
            // quitar \n
            line[strcspn(line, "\r\n")] = 0;

            if (!parse_cidr(line, &ip, &prefix)) {
                printf("Entrada invalida. Ejemplo valido: 10.0.0.5/24\n\n");
                continue;
            }
        } else if (op == 2) {
            char ip_str[128];
            printf("IP (a.b.c.d): ");
            if (!fgets(ip_str, sizeof(ip_str), stdin)) break;
            ip_str[strcspn(ip_str, "\r\n")] = 0;

            printf("Prefijo (0..32): ");
            if (scanf("%d", &prefix) != 1) break;
            clear_line();

            if (!parse_ipv4(ip_str, &ip) || prefix < 0 || prefix > 32) {
                printf("IP o prefijo invalido.\n\n");
                continue;
            }
        } else {
            printf("Opcion invalida.\n\n");
            continue;
        }

        print_subnet_info(ip, prefix);
    }

    printf("Bye.\n");
    return 0;
}
