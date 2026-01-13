#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    
    int udp_socket, lbind, tam;
    struct sockaddr_in local, remota;
    unsigned char msj[100] = "Hola red, soy David Tetuan";

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (udp_socket == -1) {
        perror("Error al abrir el socket");
        exit(EXIT_FAILURE);
    }

    else{

        perror("Exito al abrir el socket");
    
        local.sin_family = AF_INET;
        local.sin_port = htons(0);     // Puerto de escucha
        local.sin_addr.s_addr = INADDR_ANY; // Escuchar en cualquier IP de la máquina

        lbind = bind(udp_socket, (struct sockaddr *)&local, sizeof(local));

        if (lbind == -1) {
            perror("Error en bind");
            exit(0);
        }

        else{

            perror("Exito en bind");

            remota.sin_family = AF_INET;
            remota.sin_port = htons(8080); // Puerto DNS
            remota.sin_addr.s_addr = inet_addr("192.168.100.48");

            tam = sendto(udp_socket, msj, 20, 0, (struct sockaddr *)&remota, sizeof(remota));

            if (tam == -1) {
                perror("Error al enviar");
                exit(0);
            }

            else
                perror("Exito al enviar");

        }

    }
                

    close(udp_socket);
    return 0;

}
