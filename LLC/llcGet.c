#include <stdio.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

unsigned char MACorigen[6];
unsigned char tramaLLC[1514];


void imprimeTrama(unsigned char *trama, int tam);
void obtenDatos(int ds);
int recibeTramaLLC(int ds, unsigned char *trama);
int filtroLLC(unsigned char *paq, int len);


int filtroLLC(unsigned char *paq, int len){

    int longitud_campo;
    longitud_campo = (paq[12] << 8) + paq[13];

    if(longitud_campo <= 1500)
        return 1;
    
    else 
        return 0;
    
}

void obtenDatos(int ds){

    struct ifreq nic;
    char nombre[20];

    printf("\nInserta el nombre de la interfaz: ");
    if (fgets(nombre, sizeof(nombre), stdin) != NULL)
        nombre[strcspn(nombre, "\n")] = 0;
    
    strcpy(nic.ifr_name, nombre);

    if( ioctl(ds, SIOCGIFHWADDR, &nic) == -1 ){
        perror("Error al obtener la MAC");
        exit(1);
    }

    else{
        memcpy(MACorigen, nic.ifr_hwaddr.sa_data, 6);
        printf("\nMi MAC es: ");

        for(int i=0; i<6; i++)
            printf("%.2x:", MACorigen[i]);
        
        printf("\n");
    }
}

void imprimeTrama(unsigned char *trama, int tam){

    printf("\n--- Contenido del Paquete (%d bytes) ---", tam);

    for(int i=0; i<tam; i++){

        if(i%16==0)
            printf("\n");
        
        printf("%.2x ", trama[i]);
    }

    printf("\n");

}

int recibeTramaLLC(int ds, unsigned char *trama){
    
    int tam;

    long int mtime = 0;
    struct timeval start,end;
    long seconds,useconds;
    
    gettimeofday(&start,NULL);

    while(mtime < 500){

        memset(trama, 0, 1514);

        tam = recvfrom(ds, trama, 1514, 0, NULL, 0);

        if(tam == -1){
            perror("\nError al recibir");
            exit(1);
        }

        else{
            if( !memcmp(trama+0, MACorigen, 6) ){
                if (filtroLLC(trama, tam)) {
                    printf("\n-> Trama LLC detectada dirigida a mi.");
                    imprimeTrama(trama, tam);
                    printf("\n********** Proceso finalizado *************\n");
                    return tam;
                }
            }
        }

        gettimeofday(&end,NULL);

        seconds = end.tv_sec - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;

        mtime = ( (seconds) * 1000 + useconds/1000.0 ) + 0.5;

    }

    printf("\n********** Proceso finalizado por tiempo *************\n");
    return tam;
}

int main(){

    int packet_socket, tam;

    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(packet_socket == -1){
        perror("\nError al abrir el socket (necesitas sudo)");
        exit(0);
    }

    else{

        printf("Exito al abrir el socket. Esperando paquetes...\n");
        obtenDatos(packet_socket);

        while(1){

            tam = recibeTramaLLC(packet_socket, tramaLLC);
            
        }
        
    }

    close(packet_socket);
    return 0;

}