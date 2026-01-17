#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h> 
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

// --- CONFIGURACIÓN ---
#define ETH_P_ARP 0x0806
#define ARPOP_REQUEST 1
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

unsigned char MAC_MIA[6];
unsigned char IP_MIA[4];
unsigned char IP_DESTINO[4];
int interfaz_index;

// Puntero a Memoria Compartida (Para que Hijo actualice y Padre lea)
unsigned char *MAC_DESTINO_DINAMICA;

void resolverARP_Inicial(int ds) {
    struct arp_packet pkt;
    struct sockaddr_ll addr = {0};
    unsigned char buffer[1514];

    // Construir Request ARP
    memset(pkt.eth_dest, 0xFF, 6);
    memcpy(pkt.eth_src, MAC_MIA, 6);
    pkt.eth_proto = htons(ETH_P_ARP);
    pkt.arp_hw_type = htons(1);
    pkt.arp_proto_type = htons(0x0800);
    pkt.arp_hw_len = 6;
    pkt.arp_proto_len = 4;
    pkt.arp_opcode = htons(ARPOP_REQUEST);
    memcpy(pkt.sender_mac, MAC_MIA, 6);
    memcpy(pkt.sender_ip, IP_MIA, 4);
    memset(pkt.target_mac, 0x00, 6);
    memcpy(pkt.target_ip, IP_DESTINO, 4);

    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = interfaz_index;
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xFF, 6);

    printf("--> Buscando destino inicial...\n");
    sendto(ds, &pkt, sizeof(pkt), 0, (struct sockaddr*)&addr, sizeof(addr));

    while (1) {
        int len = recvfrom(ds, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len <= 0) continue;
        struct arp_packet *recibido = (struct arp_packet *)buffer;

        if (recibido->eth_proto == htons(ETH_P_ARP) &&
            recibido->arp_opcode == htons(ARPOP_REPLY) &&
            memcmp(recibido->sender_ip, IP_DESTINO, 4) == 0) {
            
            memcpy(MAC_DESTINO_DINAMICA, recibido->sender_mac, 6);
            printf("--> Conectado inicialmente.\n");
            return;
        }
    }
}

void enviarMensaje(int ds, char *texto) {
    unsigned char trama[1514];
    memset(trama, 0, sizeof(trama));

    int len_mensaje = strlen(texto);
    unsigned short longitud_net = htons(3 + len_mensaje);
    
    // Usar la MAC dinámica (puede ser la real o la del atacante)
    memcpy(trama, MAC_DESTINO_DINAMICA, 6);
    memcpy(trama + 6, MAC_MIA, 6);
    memcpy(trama + 12, &longitud_net, 2);
    
    // Firma LLC
    trama[14] = 0xF0; trama[15] = 0x0F; trama[16] = 0x7F;
    memcpy(trama + 17, texto, len_mensaje);

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = interfaz_index;

    int tam_total = 14 + 3 + len_mensaje;
    if(tam_total < 60) tam_total = 60; 

    sendto(ds, trama, tam_total, 0, (struct sockaddr*)&addr, sizeof(addr));
}

int main() {
    system("clear");
    // Crear memoria compartida
    MAC_DESTINO_DINAMICA = mmap(NULL, 6, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);

    int ds = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ds == -1) { perror("Sudo requerido"); return 1; }

    struct ifreq nic;
    char nombre_interfaz[20], ip_str[20];

    printf("--- VICTIMA (A / B) ---\n");
    printf("Interfaz: "); scanf("%s", nombre_interfaz);
    
    strcpy(nic.ifr_name, nombre_interfaz);
    ioctl(ds, SIOCGIFINDEX, &nic); interfaz_index = nic.ifr_ifindex;
    ioctl(ds, SIOCGIFHWADDR, &nic); memcpy(MAC_MIA, nic.ifr_hwaddr.sa_data, 6);

    printf("Tu IP: "); scanf("%s", ip_str); inet_pton(AF_INET, ip_str, IP_MIA);
    printf("IP Destino: "); scanf("%s", ip_str); inet_pton(AF_INET, ip_str, IP_DESTINO);

    int c; while ((c = getchar()) != '\n' && c != EOF); 

    resolverARP_Inicial(ds);

    printf("\n--- CHAT LISTO ---\n");

    pid_t pid = fork();

    if (pid == 0) {
        // --- HIJO: ESCUCHA CHAT Y ARP ---
        unsigned char buffer[1514];
        while(1) {
            memset(buffer, 0, sizeof(buffer));
            int tam = recvfrom(ds, buffer, sizeof(buffer), 0, NULL, 0);
            if (tam <= 0) continue;

            // IGNORAR MIS PROPIOS PAQUETES (ANTI-ECO)
            if (memcmp(buffer + 6, MAC_MIA, 6) == 0) continue;

            unsigned short tipo = (buffer[12] << 8) + buffer[13];

            // 1. CHAT
            if (memcmp(buffer, MAC_MIA, 6) == 0 &&
                buffer[14] == 0xF0 && buffer[15] == 0x0F && buffer[16] == 0x7F) {
                buffer[tam] = 0; // Corte limpio
                printf("\n[RECIBIDO]: %s\n> ", buffer + 17);
                fflush(stdout);
            }

            // 2. ARP (Actualización dinámica)
            if (tipo == ETH_P_ARP) {
                struct arp_packet *arp = (struct arp_packet *)buffer;
                if (arp->arp_opcode == htons(ARPOP_REPLY) &&
                    memcmp(arp->sender_ip, IP_DESTINO, 4) == 0) {
                    
                    if (memcmp(MAC_DESTINO_DINAMICA, arp->sender_mac, 6) != 0) {
                        memcpy(MAC_DESTINO_DINAMICA, arp->sender_mac, 6);
                        // printf("\n[INFO] Ruta actualizada.\n> "); fflush(stdout);
                    }
                }
            }
        }
    } else {
        // --- PADRE: ENVÍA ---
        char msj[100];
        while(1) {
            printf("> ");
            if (fgets(msj, 100, stdin)) {
                msj[strcspn(msj, "\n")] = 0;
                if(strlen(msj) > 0) enviarMensaje(ds, msj);
            }
        }
    }
    munmap(MAC_DESTINO_DINAMICA, 6);
    close(ds);
    return 0;
}