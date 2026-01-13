#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

unsigned char MACorigen[6];
unsigned char tramaLLC[1514];


int obtenDatos(int ds);
void enviaTrama(int ds, int index, unsigned char *paq, int tam_total);
void estructuraTramaLLC(unsigned char *trama, char *mensaje);
void imprimeTrama(unsigned char *trama, int tam);


void enviaTrama(int ds, int index, unsigned char *paq, int tam_total) {

    struct sockaddr_ll capaEnlace;
    int enviados;

    memset(&capaEnlace, 0x00, sizeof(capaEnlace));

    capaEnlace.sll_family = AF_PACKET;
    capaEnlace.sll_protocol = htons(ETH_P_ALL);
    capaEnlace.sll_ifindex = index;

    enviados = sendto(ds, paq, tam_total, 0, (struct sockaddr*)&capaEnlace, sizeof(capaEnlace));

    if (enviados == -1)
        perror("\nError al enviar la trama");

    else
        printf("\nExito al enviar la trama (%d bytes)\n", enviados);

}

void estructuraTramaLLC(unsigned char *trama, char *mensaje) {

    int len_mensaje = strlen(mensaje);
    int longitud_campo = 3 + len_mensaje;
    unsigned short longitud_net = htons(longitud_campo);

    memcpy(trama + 0, MACorigen, 6);
    memcpy(trama + 6, MACorigen, 6);
    memcpy(trama + 12, &longitud_net, 2);

    trama[14] = 0xF0;
    trama[15] = 0x0F;
    trama[16] = 0x7F;

    memcpy(trama + 17, mensaje, len_mensaje);
}

int obtenDatos(int ds) {
    struct ifreq nic;
    char nombre[20];
    int index;

    printf("\nInserta el nombre de la interfaz: ");
    if (fgets(nombre, sizeof(nombre), stdin) != NULL) {
        nombre[strcspn(nombre, "\n")] = 0;
    }
    strcpy(nic.ifr_name, nombre);

    if (ioctl(ds, SIOCGIFINDEX, &nic) == -1) {
        perror("Error obteniendo index"); exit(1);
    }
    index = nic.ifr_ifindex;

    if (ioctl(ds, SIOCGIFHWADDR, &nic) == -1) {
        perror("Error obteniendo MAC"); exit(1);
    }
    memcpy(MACorigen, nic.ifr_hwaddr.sa_data, 6);

    return index;
}

void imprimeTrama(unsigned char *trama, int tam) {
    for (int i = 0; i < tam; i++) {
        if (i % 16 == 0) printf("\n");
        printf("%.2x ", trama[i]);
    }
    printf("\n");
}

int main() {

    int packet_socket, indice;
    char *miMensaje = "Ya funciona, espero jaja";

    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (packet_socket == -1) {
        perror("\nError al abrir el socket");
        exit(1);
    }

    printf("Exito al abrir el socket\n");
    indice = obtenDatos(packet_socket);
    estructuraTramaLLC(tramaLLC, miMensaje);
    int tam_total = 14 + 3 + strlen(miMensaje);
    if(tam_total < 60) tam_total = 60;

    printf("\n********** Trama a enviar *************\n");
    imprimeTrama(tramaLLC, tam_total);
    
        enviaTrama(packet_socket, indice, tramaLLC, tam_total);

    close(packet_socket);
    return 0;

}