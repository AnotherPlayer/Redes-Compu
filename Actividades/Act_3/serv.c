#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void writeText( char* msj ){

    printf("\nEscribe un mensaje (Servidor): \n");
    fgets(msj, 512, stdin);
    msj[strcspn(msj, "\n")] = 0;

}

int main() {

    int udp_socket, lbind, tam, lrecv;
    struct sockaddr_in servidor, cliente;
    unsigned char msj[512];
    unsigned char paqRec[512];
    socklen_t len_cliente;

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_socket == -1){
        perror("Error al abrir el socket");
        exit(EXIT_FAILURE);
    }
    else{

        perror("Exito al abrir el socket");
    
        memset(&servidor, 0, sizeof(servidor));
    
        servidor.sin_family = AF_INET;
        servidor.sin_port = htons(8080);     // Puerto de escucha
        servidor.sin_addr.s_addr = INADDR_ANY; // Escuchar en cualquier IP de la máquina

        lbind = bind(udp_socket, (struct sockaddr *)&servidor, sizeof(servidor));

        if(lbind == -1){
            perror("Error en bind");
            exit(EXIT_FAILURE);
        }
        else{

            perror("Exito en bind");

            while (1){
            
                lrecv = sizeof(cliente);
                tam = recvfrom(udp_socket, paqRec, 512, 0, (struct sockaddr *)&cliente, &lrecv);

                if(tam == -1){
                    perror("Error al recibir");
                    exit(0);
                }
                else 
                    printf("\nEl mensaje recibido es: %s\n", paqRec);

                writeText(msj);
            
                tam = sendto(udp_socket, msj, 512, 0, (struct sockaddr *)&cliente, sizeof(cliente));
            
                if(tam == -1){
                    perror("Error al enviar");
                    exit(0);
                }
                else
                    printf("\nEnviando mensaje a Usuario: %s\n", msj);

            }
        }
    }

    close(udp_socket);
    return 0;

}