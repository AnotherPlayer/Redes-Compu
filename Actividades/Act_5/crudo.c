#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

unsigned char MACorigen[6];
unsigned char IPorigen[4];
unsigned char MascaraDeSubred[4];

void obtenDatos(int ds) {

    struct ifreq nic;
    unsigned char nombre[20];
    int indice;

    printf("\nInserta el nombre de la interfaz: ");
    gets(nombre);
    strcpy(nic.ifr_name, nombre);

    //Confirmar obtención del Índice
    if (ioctl(ds, SIOCGIFINDEX, &nic) == -1) {
        perror("\nError al obtener el index");
        exit(0);
    }

    indice = nic.ifr_ifindex;

    //Confirmar obtención de la MAC
    if (ioctl(ds, SIOCGIFHWADDR, &nic) == -1) {
        perror("\nError al obtener la MAC");
        exit(0);
    }

    memcpy(MACorigen, nic.ifr_hwaddr.sa_data, 6);

    //Confirmar obtención de la Dirección IP
    if (ioctl(ds, SIOCGIFADDR, &nic) == -1) {
        perror("\nError al obtener la Direccion IP");
        exit(0);
    }

    struct sockaddr_in *ip = (struct sockaddr_in *)&nic.ifr_addr;
    memcpy(IPorigen, &ip->sin_addr, 4);

    //Confirmar obtención de la Máscara de Subred
    if (ioctl(ds, SIOCGIFNETMASK, &nic) == -1) {
        perror("\nError al obtener la Mascara de Subred");
        exit(0);
    }

    struct sockaddr_in *mascara = (struct sockaddr_in *)&nic.ifr_netmask;
    memcpy(MascaraDeSubred, &mascara->sin_addr, 4);

    printf("\nEl indice es: %d", indice);

    printf("\nLa MAC es: %02x:%02x:%02x:%02x:%02x:%02x", 
        MACorigen[0], MACorigen[1], MACorigen[2], 
        MACorigen[3], MACorigen[4], MACorigen[5]);

    printf("\nLa Direccion IP es: %d.%d.%d.%d", 
        IPorigen[0], IPorigen[1], IPorigen[2], IPorigen[3]);

    printf("\nLa Mascara de Subred es: %d.%d.%d.%d\n", 
        MascaraDeSubred[0], MascaraDeSubred[1], 
        MascaraDeSubred[2], MascaraDeSubred[3]);

}

int main() {
    int packet_socket;

    // Apertura del socket siguiendo el estilo del repositorio
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (packet_socket == -1) {
        perror("\nError al abrir el socket");
        exit(0);
    } else {
        perror("\nExito al abrir el socket");
        obtenDatos(packet_socket);
    }

    close(packet_socket);
    return 0;
}