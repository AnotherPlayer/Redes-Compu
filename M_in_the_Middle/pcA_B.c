#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>

unsigned char MACorigen[6];
unsigned char MACdestino[6];
int interfaz_index;

// Convierte el formato aa:bb:cc... a bytes
void stringToMac(char *macStr, unsigned char *macBytes) {
    sscanf(macStr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &macBytes[0], &macBytes[1], &macBytes[2], 
           &macBytes[3], &macBytes[4], &macBytes[5]);
}

void configurarInterfaz(int ds) {
    struct ifreq nic;
    char nombre[20], macStr[20];
    
    printf("Nombre de tu interfaz (ej. eth0, enp3s0): ");
    scanf("%s", nombre);
    
    printf("MAC de la OTRA computadora (ej. aa:bb:cc:dd:ee:ff): ");
    scanf("%s", macStr);
    stringToMac(macStr, MACdestino);

    strcpy(nic.ifr_name, nombre);
    if (ioctl(ds, SIOCGIFINDEX, &nic) == -1) { 
        perror("Error al obtener el índice de la interfaz"); 
        exit(1); 
    }
    interfaz_index = nic.ifr_ifindex;

    if (ioctl(ds, SIOCGIFHWADDR, &nic) == -1) { 
        perror("Error al obtener tu dirección MAC"); 
        exit(1); 
    }
    memcpy(MACorigen, nic.ifr_hwaddr.sa_data, 6);
    
    // Limpiar el buffer de entrada para evitar que el primer mensaje se envíe vacío
    int c;
    while ((c = getchar()) != '\n' && c != EOF); 
}

void enviarMensaje(int ds, char *texto) {
    unsigned char trama[1514];
    memset(trama, 0, 1514); // Limpieza total de la trama antes de construirla

    int len_mensaje = strlen(texto);
    unsigned short longitud_net = htons(3 + len_mensaje);
    
    // Construcción de la trama Ethernet
    memcpy(trama + 0, MACdestino, 6);
    memcpy(trama + 6, MACorigen, 6);
    memcpy(trama + 12, &longitud_net, 2);
    
    // Cabecera LLC
    trama[14] = 0xF0; 
    trama[15] = 0x0F; 
    trama[16] = 0x7F;
    
    // Datos del mensaje
    memcpy(trama + 17, texto, len_mensaje);

    struct sockaddr_ll capaEnlace;
    memset(&capaEnlace, 0x00, sizeof(capaEnlace));
    capaEnlace.sll_family = AF_PACKET;
    capaEnlace.sll_ifindex = interfaz_index;

    int tam_total = 14 + 3 + len_mensaje;
    if(tam_total < 60) tam_total = 60; // Relleno (padding) mínimo para Ethernet

    if (sendto(ds, trama, tam_total, 0, (struct sockaddr*)&capaEnlace, sizeof(capaEnlace)) == -1) {
        perror("Error al enviar el mensaje");
    }
}

int main() {
    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (packet_socket == -1) { 
        perror("Error al abrir el socket (¿olvidaste el sudo?)"); 
        exit(1); 
    }

    configurarInterfaz(packet_socket);
    printf("\n--- CHAT DE CAPA 2 INICIADO ---\n");
    printf("Escribe tu mensaje y presiona Enter. Escribe 'salir' para finalizar.\n\n");

    pid_t pid = fork();

    if (pid < 0) { 
        perror("Error al crear el proceso"); 
        exit(1); 
    }

    if (pid == 0) {
        // PROCESO HIJO: Encargado de RECIBIR
        unsigned char buffer[1514];
        while (1) {
            memset(buffer, 0, 1514); // Limpiar buffer receptor para evitar basura
            int tam = recvfrom(packet_socket, buffer, 1514, 0, NULL, 0);
            
            if (tam > 0) {
                // Filtro: Debe ser para nosotros y cumplir formato LLC
                int longitud = (buffer[12] << 8) + buffer[13];
                if (memcmp(buffer, MACorigen, 6) == 0 && longitud <= 1500) {
                    printf("\n[MENSAJE RECIBIDO]: %s\n> ", buffer + 17);
                    fflush(stdout);
                }
            }
        }
    } else {
        // PROCESO PADRE: Encargado de ENVIAR
        char mensaje[100];
        while (1) {
            printf("> ");
            if (fgets(mensaje, sizeof(mensaje), stdin) != NULL) {
                mensaje[strcspn(mensaje, "\n")] = 0; // Eliminar el salto de línea

                if (strlen(mensaje) == 0) continue;

                if (strcmp(mensaje, "salir") == 0) {
                    kill(pid, SIGKILL); // Terminar proceso hijo
                    break;
                }
                enviarMensaje(packet_socket, mensaje);
            }
        }
    }

    close(packet_socket);
    printf("\nChat finalizado.\n");
    return 0;
}
