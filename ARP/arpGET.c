//Obtener (Reply)

#include <stdio.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

unsigned char tramaARPresp[1514];

unsigned char MACorigen[6];
unsigned char IPorigen[4];
unsigned char IPdestino[4];
unsigned char etherARP[2]={0x08,0x06};
unsigned char codARPresp[2]={0x00,0x02};
unsigned char Mascara[4];

int obtenDatos( int ds );
int filtroARP( unsigned char *paq,int len );
void recibeARPresp( int ds,unsigned char *trama );
void imprimeTrama( unsigned char *trama, int tam );
void imprimeIPMAC( unsigned char *trama );

//Check --> Parece estar bien
int obtenDatos( int ds ){

    struct ifreq red;
    char nombre[20];
    int indice;

    // 1. Solicitar el nombre de la interfaz al usuario
    printf("\nIngresa el nombre de la interfaz de red (ej. eth0, wlan0): ");
    scanf("%s", nombre);

    //Obtener índice
    strcpy(red.ifr_name, nombre);
    
    if (ioctl(ds, SIOCGIFINDEX, &red) == -1) {
        perror("\nError al obtener el indice de la interfaz");
        exit(0);
    }

    indice = red.ifr_ifindex;
    printf("\n-> Indice obtenido: %d", indice);

    //Obtener MAC
    strcpy(red.ifr_name, nombre);
    
    if (ioctl(ds, SIOCGIFHWADDR, &red) == -1) {
        perror("\nError al obtener la direccion MAC");
        exit(0);
    }
    
    memcpy(MACorigen, red.ifr_hwaddr.sa_data, 6);
    
    printf("\n-> MAC obtenida: %02X:%02X:%02X:%02X:%02X:%02X", 
           MACorigen[0], MACorigen[1], MACorigen[2], 
           MACorigen[3], MACorigen[4], MACorigen[5]);

    //Obtener la IP
    strcpy(red.ifr_name, nombre);
    
    if (ioctl(ds, SIOCGIFADDR, &red) == -1) {
        perror("\nError al obtener la direccion IP");
        exit(0);
    }
    
    memcpy(IPorigen, red.ifr_addr.sa_data + 2, 4);
    
    printf("\n-> IP obtenida: %d.%d.%d.%d\n", 
           IPorigen[0], IPorigen[1], IPorigen[2], IPorigen[3]);

    return indice;

}

//Done --> Es del libro
int filtroARP( unsigned char *paq,int len ){

    if(!memcmp(paq,MACorigen,6)){
        if(!memcmp(paq+12,etherARP,2))
            if(!memcmp(paq+20,codARPresp,2))
                if(!memcmp(paq+38,IPorigen,4))
                    return 1;
    }

    else
        return 0;

}

//Done --> Es del libro
void recibeARPresp( int ds,unsigned char *trama ){

    int tam,bandera=0;

    //Agregar límite de tiempo
    long int mtime = 0;
    struct timeval start,end;
    long seconds,useconds;

    gettimeofday(&start,NULL);

    while(mtime < 5000){

        tam = recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);

        if(tam==-1)
            perror("\nError al recibir");
            
        else{
            
            bandera = filtroARP(trama,tam);

            if(bandera == 1)
                return;
            
        }

        //Leer tiempo
        gettimeofday(&end,NULL);

        seconds = end.tv_sec - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;

        mtime = ( (seconds) * 1000 + useconds/1000.0 ) + 0.5;

    }

}

//Check --> Parece estar bien
void imprimeTrama( unsigned char *trama, int tam ) {
    
    int i;

    for(i = 0; i < tam; i++) {

        if(i % 16 == 0) printf("\n");
            printf("%.2x ", trama[i]);

    }

    printf("\n");

}

//Check --> Parece estar bien
void imprimeIPMAC( unsigned char *trama ){

    printf("-> IP: %d.%d.%d.%d  |  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           trama[28], trama[29], trama[30], trama[31],
           trama[22], trama[23], trama[24], trama[25], trama[26], trama[27]);

}

//Check --> Parece estar bien
void monitorRespuestas(int ds) {
    int tam, bandera;
    unsigned char trama[1514];

    printf("\n********** Monitor de Red Activo **********\n");
    printf("Esperando respuestas de hosts activos... (Presiona Ctrl+C para salir)\n\n");

    while(1) {
        // Recibir trama (Bloquear para poder gestionar el flujo si fuera necesario)
        tam = recvfrom(ds, trama, 1514, MSG_DONTWAIT, NULL, 0);

        if(tam > 0) {
            
            bandera = filtroARP(trama, tam);

            if(bandera == 1) {
                printf("[!] Host Encontrado: ");
                imprimeIPMAC(trama);
            }
        }
        
        // Pequeña pausa de 1ms para no saturar el procesador con el bucle infinito
        usleep(1000); 
    }
}

//Done --> Es del libro
int main(){

    int packet_socket,indice;
    packet_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    if(packet_socket==-1){

        perror("\nError al abrir el socket");
        exit(0);

    }

    else{

        perror("Exito al abrir el socket");

        indice = obtenDatos(packet_socket);
        
        recibeARPresp(packet_socket,tramaARPresp);

        monitorRespuestas(packet_socket);

        //printf("\n**********La trama que se recibe de respuesta ARP's*************\n");

        //imprimeTrama(tramaARPresp,60);
        //imprimeIPMAC(tramaARPresp);

    }

    close(packet_socket);
    return 1;

}