#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>/* the L2 protocols */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

#define MACorigen 0

void obtenerDatos(int ds){

  struct ifreq nic;
  unsigned char nombre[20];
  printf("\nInserta el nombre de la interfaz: ");
  gets(nombre);
  strcpy(nic.ifr_name,nombre);

  if(ioctl(ds, SIOCGIFINDEX,&nic)==-1){
    perror("Error al obtener el index");
    exit(0);
  }

  else
    printf("\nEl indice es: %d \n\n",nic.ifr_ifindex);

  if(ioctl(ds, SIOCGIFHWADDR,&nic)==-1){
    perror("Error al obtener la direccion MAC");
    exit(0);
  }

  else{

    memcpy(nic.ifr_hwaddr.sa_data, nic.ifr_hwaddr.sa_data,6);
    //memcpy(MACorigen, nic.ifr_hwaddr.sa_data,6);

    for(int i=0;i<6;i++){
      printf("%.2x", (unsigned char)nic.ifr_hwaddr.sa_data[i]);
      //printf("%.2x", MACorigen[i]);
      if(i<5){
        printf(":");
      }
    }
    printf("\n\n");
  }

  /* Obtener máscara de subred */
  
  if(ioctl(ds, SIOCGIFNETMASK, &nic) == -1){

    perror("Error al obtener la máscara de subred");
    exit(0);

  }

  else{

    struct sockaddr_in *mask = (struct sockaddr_in *)&nic.ifr_addr;
    char mask_str[INET_ADDRSTRLEN];

    if(inet_ntop(AF_INET, &mask->sin_addr, mask_str, sizeof(mask_str)) == NULL)
      perror("Error al convertir la máscara");
    
    else
      printf("Máscara de subred: %s\n\n", mask_str);
    
  }


}

int main(){

  int packet_socket;
  packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if(packet_socket==-1){

    perror("\nError al abrir el socket");
    exit(0);

  }

  else{

  perror("\nExito al abrir el socket");
  obtenerDatos(packet_socket);

  }

close(packet_socket);
return 0;

}
