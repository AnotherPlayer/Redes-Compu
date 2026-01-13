#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <string.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

unsigned char MACorigen[6];
unsigned char IPorigen[4];
unsigned char MascaraDeSubred[4];

unsigned char MACbroadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char ethertype[2] = {0x0c, 0x0c};
unsigned char tramaEnv[1514];

int obtenDatos(int ds) {

    struct ifreq nic;
    unsigned char nombre[20];
    int indice;

    printf("\nInserta el nombre de la interfaz: ");
    gets(nombre);
    strcpy(nic.ifr_name, nombre);

    // Confirmar obtención del Índice
    if (ioctl(ds, SIOCGIFINDEX, &nic) == -1) {
        perror("\nError al obtener el index");
        exit(0);
    }

    indice = nic.ifr_ifindex;

    // Confirmar obtención de la MAC
    if (ioctl(ds, SIOCGIFHWADDR, &nic) == -1) {
        perror("\nError al obtener la MAC");
        exit(0);
    }

    memcpy(MACorigen, nic.ifr_hwaddr.sa_data, 6);

    // Confirmar obtención de la Dirección IP
    if (ioctl(ds, SIOCGIFADDR, &nic) == -1) {
        perror("\nError al obtener la Direccion IP");
        exit(0);
    }

    struct sockaddr_in *ip = (struct sockaddr_in *)&nic.ifr_addr;
    memcpy(IPorigen, &ip->sin_addr, 4);

    // Confirmar obtención de la Máscara de Subred
    if (ioctl(ds, SIOCGIFNETMASK, &nic) == -1) {
        perror("\nError al obtener la Mascara de Subred");
        exit(0);
    }

    struct sockaddr_in *mascara = (struct sockaddr_in *)&nic.ifr_netmask;
    memcpy(MascaraDeSubred, &mascara->sin_addr, 4);

    // Impresión de parámetros recolectados
    printf("\nEl indice es: %d", indice);

    printf("\nLa MAC es: %02x:%02x:%02x:%02x:%02x:%02x", 
            MACorigen[0], MACorigen[1], MACorigen[2], 
            MACorigen[3], MACorigen[4], MACorigen[5]);

    printf("\nLa Direccion IP es: %d.%d.%d.%d", 
            IPorigen[0], IPorigen[1], IPorigen[2], IPorigen[3]);

    printf("\nLa Mascara de Subred es: %d.%d.%d.%d\n", 
            MascaraDeSubred[0], MascaraDeSubred[1], 
            MascaraDeSubred[2], MascaraDeSubred[3]);

    return indice;

}

void estructuraTrama(unsigned char *trama) {

    memcpy(trama + 0, MACbroadcast, 6);
    memcpy(trama + 6, MACorigen, 6);
    memcpy(trama + 12, ethertype, 2);
    memcpy(trama + 14, "Tetuan", 7);

}

void enviarTrama(int ds, int index, unsigned char *trama) {

    int tam;
    struct sockaddr_ll interfaz;
    memset(&interfaz, 0x00, sizeof(interfaz));
    interfaz.sll_family = AF_PACKET;
    interfaz.sll_protocol = htons(ETH_P_ALL);
    interfaz.sll_ifindex = index;
    
    tam = sendto(ds, trama, 60, 0, (struct sockaddr *)&interfaz, sizeof(interfaz));

    if (tam == -1) {
        perror("\nError al enviar");
        exit(1);
    }
    
    else
        perror("\nExito al enviar");
    
}

void imprimirTrama(unsigned char *paq, int len){

  for(int i=0; i<len; i++){

    if(i%16==0)
      printf("\n");
    
    printf("%.2x ", paq[i]);

  }

  printf("\n");

}

bool filtros(unsigned char *trama) {

    if (!(memcmp(trama + 0, MACorigen, 6)))
        return true;
    
    if (!(memcmp(trama + 6, MACorigen, 6)))
        return true;
    
    return false;
}

void recibirTrama(int ds, unsigned char *trama){

  int tam;

    while(1){

        memset(trama, 0, 1514);
        tam = recvfrom(ds, trama, 1514, 0, NULL, 0);

        if(tam==-1){

            perror("\nError al recibir");
            exit(0);

        }

        else{
            if(filtros(trama)){
                imprimirTrama(trama, tam);
                break;
            }
        }
    }

}

int main() {
    
    int packet_socket,indice;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (packet_socket == -1) {

        perror("\nError al abrir el socket");
        exit(0);

    }
    
    else {

        perror("\nExito al abrir el socket");
        indice = obtenDatos(packet_socket);

        recibirTrama(packet_socket, tramaEnv);

    }

    close(packet_socket);
    return 0;
}