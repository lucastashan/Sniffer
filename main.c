/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/tcp.h>	//Provides declarations for tcp header

#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

void process_packet();
void print_tcp_packet();
void print_ipv4_header();
void print_ipv6_header();
void print_ethernet_header();


// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;
  int total=0, tcp=0, others=0;

int main(int argc,char *argv[])
{
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    sockd = (socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)));
    if(sockd < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
  //printf("%d\n%s\n", sockd, ifr.ifr_name);
	strcpy(ifr.ifr_name, "eth0");
  //printf("%d \n", ioctl(sockd, SIOCGIFINDEX, &ifr));
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
 
	// recepcao de pacotes
	while (1) {
   	int data_size = recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
    if (data_size < 0)
    {
      printf("Recv error, failed to get packets\n");
      return 1;
    }
     
		// impressao do conteudo - exemplo Endereco Destino e Endereco Origem
		printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
		printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
    // if( buff1[12] == 0x86 && buff1[13] == 0xdd ) {
      
    // }
    //printf("Length: 0x%x%x\n\n", buff1[12], buff1[13]);
    process_packet();
	}
}

void process_packet() {
  //Get the IP Header part of this packet
  //struct iphdr *iph = (struct iphdr *)&buff1[14];
  //struct ether_header *prot = (struct ether_header *)&buff1[12];
  struct ethhdr *eth = (struct ethhdr *)&buff1[0];
  
  total++;
  print_ethernet_header();
  switch (htons(eth->h_proto)){
    // Trafego IPv4
    case ETHERTYPE_IP:
      print_ipv4_header();
      break;
    // Trafego IPv6
    case ETHERTYPE_IPV6:
      break;
    default:
      others++;
      break;
  }  
}

void print_ethernet_header() {
  struct ethhdr *eth = (struct ethhdr *)&buff1[0];

  printf("\nEthernet Header\n");
  printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  printf("   |-Protocol            : 0x%x \n",htons(eth->h_proto));
}

void print_tcp_packet() {
  unsigned short iphdrlen;
  struct iphdr *iph = (struct iphdr *)&buff1[14];
  iphdrlen = iph->ihl*4;
  
  struct tcphdr *tcph = (struct tcphdr*)(&buff1[14] + iphdrlen);   

  printf("----------------TCP Packet----------------\n");

  printf("\nTCP Header:\n");
  printf("       | -Source Port: %u\n", ntohs(tcph->source));
  printf("       | -Destination Port: %u\n", ntohs(tcph->dest));
  printf("       | -Sequence number: %u\n", ntohl(tcph->seq));
  printf("       | -Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
  printf("       | -Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  printf("       | -Urgent Flag         : %d\n",(unsigned int)tcph->urg);
  printf("       | -Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  printf("       | -Push Flag            : %d\n",(unsigned int)tcph->psh);
	printf("       | -Reset Flag           : %d\n",(unsigned int)tcph->rst);
	printf("       | -Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	printf("       | -Finish Flag          : %d\n",(unsigned int)tcph->fin);
  printf("       | -Window: %d\n",ntohs(tcph->window));
  printf("       | -Checksum       : %d\n",ntohs(tcph->check));
  printf("       | -Urgent Pointer : %d\n",tcph->urg_ptr);
}

void print_ipv4_header() {
  //Get the IP Header part of this packet
  struct iphdr *iph = (struct iphdr *)&buff1[14];
 
  printf("IPv4 Header\n");
  printf("    | -IP version: %d\n", iph->version);
  printf("    | -IP Header Length: %d Bytes\n", ((unsigned int)(iph->ihl))*4);
  printf("    | -Type of service: %d\n", (unsigned int)iph->tos);
  printf("    | -Total length: %d Bytes(size of packet)\n", ntohs(iph->tot_len));
  printf("    | -Identification: %d\n", ntohs(iph->id));
  printf("    | -TTL: %d\n", (unsigned int)iph->ttl);
  printf("    | -Protocol: %d\n", (unsigned int)iph->protocol);
  printf("    | -Checksum: %d\n", ntohs(iph->check));

  if( (unsigned int)iph->protocol == 6 ) print_tcp_packet();
}

// void print_ipv6_header() {
//   //Get the IP Header part of this packet
//   struct in6_addr *iph = (struct in6_addr *)&buff1[14];

//   printf("IPv6 Header\n");
//   printf("    | -IP version: %d\n", iph->);
// }
