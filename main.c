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
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/icmp6.h>	//Provides declarations for icmpv6 header
#include <netinet/ip_icmp.h>	//Provides declarations for icmp header
#include <net/if_arp.h>	//Provides declarations for arp header

#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

void process_packet();
void print_tcp_packet();
void print_ipv4_header();
void print_ipv6_header();
void print_ethernet_header();
void print_udp_packet();
void print_icmpv6_packet();
void print_arp_header();
float getPercent();


// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

  FILE *logfile; //Arquivo de saida

  unsigned char buff1[BUFFSIZE]; // buffer de recepcao

  int sockd;
  int on;
  struct ifreq ifr;
  int total=0, arp=0, ipv4=0, ipv6=0, icmp=0,
  icmpv6=0, tcp=0, udp=0, others=0;
  int transfhttps=0, transfdns=0;
  int rechttps=0, recdns=0;

struct ipv6_header
{
  unsigned int traffic_class1:4;		
  unsigned int version:4;
  unsigned int traffic_class2:4;
  unsigned int flow_label : 20;
  uint16_t length;
  uint8_t  next_header;
  uint8_t  hop_limit;
  struct in6_addr src;
  struct in6_addr dst;
};

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
		printf("erro no ioctl!\n");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

  // Abertura do arquivo de log
  logfile = fopen("log.txt","w");
  if(logfile==NULL) printf("Unable to create file.");

  char sair [256];
  int aux;
  printf("Starting...\n");
 	// recepcao de pacotes
	for(int i = 0; i < 100; i++) {
   	int data_size = recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
    if (data_size < 0)
    {
      printf("Recv error, failed to get packets\n");
      return 1;
    }
     
		// impressao do conteudo - exemplo Endereco Destino e Endereco Origem
		//printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
		//printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);
    // if( buff1[12] == 0x86 && buff1[13] == 0xdd ) {
      
    // }
    //printf("Length: 0x%x%x\n\n", buff1[12], buff1[13]);
    process_packet();
	}
  // Relatorio
  fprintf(logfile,"\n-------Estatística----------\n");
  fprintf(logfile,"- Total de pacotes capturados: %d\n", total);
  fprintf(logfile,"- Pacotes ARP: %.2f%%\n", getPercent(arp));
  fprintf(logfile,"- Pacotes IPv6: %.2f%%\n", getPercent(ipv6));
  fprintf(logfile,"- Pacotes IPv4: %.2f%%\n", getPercent(ipv4));
  fprintf(logfile,"- Pacotes ICMP: %.2f%%\n", getPercent(icmp));
  fprintf(logfile,"- Pacotes ICMPv6: %.2f%%\n", getPercent(icmpv6));
  fprintf(logfile,"- Pacotes TCP: %.2f%%\n", getPercent(tcp));
  fprintf(logfile,"- Pacotes UDP: %.2f%%\n", getPercent(udp));
  fprintf(logfile,"- Outros: %d\n", others);
  fprintf(logfile,"- Protocolo de aplicação mais usado nas transmissões: %d\n", others);
  fprintf(logfile,"- Protocolo de aplicação mais usado nas recepções: %d\n", others);

  fclose(logfile);
  close(sockd);
  printf("Finished.\n");
  return 0;
}

float getPercent(int value){
  return (float)((value*100)/total);
}

void process_packet() {
  //Get the IP Header part of this packet
  //struct iphdr *iph = (struct iphdr *)&buff1[14];
  //struct ether_header *prot = (struct ether_header *)&buff1[12];
  struct ethhdr *eth = (struct ethhdr *)&buff1[0];
  
  total++;
  // Mostra o cabecalho ethernet
  print_ethernet_header();

   switch (htons(eth->h_proto)){
    // Trafego IPv4
    case ETHERTYPE_IP:
      print_ipv4_header();
      ipv4++;
      break;
    // Trafego IPv6
    case ETHERTYPE_IPV6:
      print_ipv6_header();
      ipv6++;
      break;
    case ETHERTYPE_ARP:
      print_arp_header();
      arp++;
      break;
    default:
      others++;
      break;
  }  
}

void print_ethernet_header() {
  struct ethhdr *eth = (struct ethhdr *)&buff1[0];

  fprintf(logfile,"Ethernet Header\n");
  fprintf(logfile,"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  fprintf(logfile,"   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  fprintf(logfile,"   |-Protocol            : 0x%x \n",htons(eth->h_proto));
}

void print_tcp_packet(int leng) {
  unsigned short iphdrlen;
  struct iphdr *iph = (struct iphdr *)&buff1[(14+leng)];
  iphdrlen = iph->ihl*4;
  
  struct tcphdr *tcph = (struct tcphdr*)(&buff1[(14+leng)]);   

  fprintf(logfile,"----------------TCP Packet----------------\n");
  fprintf(logfile,"\nTCP Header:\n");
  fprintf(logfile,"   | -Source Port: %u\n", ntohs(tcph->source));
  fprintf(logfile,"   | -Destination Port: %u\n", ntohs(tcph->dest));
  fprintf(logfile,"   | -Sequence number: %u\n", ntohl(tcph->seq));
  fprintf(logfile,"   | -Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
  fprintf(logfile,"   | -Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
  fprintf(logfile,"   | -Urgent Flag         : %d\n",(unsigned int)tcph->urg);
  fprintf(logfile,"   | -Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
  fprintf(logfile,"   | -Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfile,"   | -Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfile,"   | -Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfile,"   | -Finish Flag          : %d\n",(unsigned int)tcph->fin);
  fprintf(logfile,"   | -Window: %d\n",ntohs(tcph->window));
  fprintf(logfile,"   | -Checksum       : %d\n",ntohs(tcph->check));
  fprintf(logfile,"   | -Urgent Pointer : %d\n",tcph->urg_ptr);

  // Protocolo de aplicacao
  if( ntohs(tcph->source) == 443 || ntohs(tcph->dest) == 443 ) {
    fprintf(logfile," * Aplicação HTTPS * \n");
    if( ntohs(tcph->source) == 443 ) transfhttps++;
    else rechttps++;
  } else if( ntohs(tcph->source) == 53 || ntohs(tcph->source) == 53 ){
    fprintf(logfile," * Aplicação DNS * \n");
    if( ntohs(tcph->source) == 53 ) transfdns++;
    else recdns++;
  }
  tcp++;
}

void print_udp_packet(int leng){

  struct udphdr *udph = (struct udphdr*)&buff1[(14+leng)];
	
  fprintf(logfile,"\n***********************UDP Packet*************************\n");			
  fprintf(logfile,"UDP Header\n");
  fprintf(logfile,"   | -Source Port      : %d\n" , ntohs(udph->source));
  fprintf(logfile,"   | -Destination Port : %d\n" , ntohs(udph->dest));
  fprintf(logfile,"   | -UDP Length       : %d Bytes\n" , ntohs(udph->len));
  fprintf(logfile,"   | -UDP Checksum     : %d\n" , ntohs(udph->check));

  // Protocolo de aplicacao
  if( ntohs(udph->source) == 443 || ntohs(udph->dest) == 443 ) {
    fprintf(logfile," * Aplicação HTTPS * \n");
    if( ntohs(udph->source) == 443 ) transfhttps++;
    else rechttps++;
  } else if( ntohs(udph->source) == 53 || ntohs(udph->dest) == 53 ){
    fprintf(logfile," * Aplicação DNS * \n");
    if( ntohs(udph->source) == 53 ) transfdns++;
    else recdns++;
  } 
  udp++;
}

void print_icmp_packet(int leng) {
  struct icmp *icmph = (struct icmp *)&buff1[leng+14];

  fprintf(logfile,"ICMP Header\n");
  fprintf(logfile,"   | -Type     : %d\n", icmph->icmp_type);
  fprintf(logfile,"   | -Code     : %d\n", icmph->icmp_code);
  fprintf(logfile,"   | -Checksum : %d\n", icmph->icmp_cksum);
  icmp++;
}

void print_icmpv6_packet() {
  struct icmp6_hdr *icmpv6 = (struct icmp6_hdr *)&buff1[54];

  fprintf(logfile,"ICMPv6 Header\n");
  fprintf(logfile,"   | -Type     : %d\n", icmpv6->icmp6_type);
  fprintf(logfile,"   | -Code     : %d\n", icmpv6->icmp6_code);
  fprintf(logfile,"   | -Checksum : %d\n", icmpv6->icmp6_cksum);
  icmpv6++;
}

void print_ipv4_header() {
  //Get the IP Header part of this packet
  struct ip *ip4 = (struct ip *)&buff1[14];
  int hleng = (ip4->ip_hl)*4;
 
  fprintf(logfile,"IPv4 Header\n");
  fprintf(logfile,"   | -IP version       : %d\n", ip4->ip_v);
  fprintf(logfile,"   | -IP Header Length : %u Bytes\n", hleng);
  fprintf(logfile,"   | -Type of service  : %d\n", (unsigned int)ip4->ip_tos);
  fprintf(logfile,"   | -Total length     : %d Bytes(size of packet)\n", ntohs(ip4->ip_len));
  fprintf(logfile,"   | -Identification   : %d\n", ntohs(ip4->ip_id));
  fprintf(logfile,"   | -Fragment Offset  : %d\n", ip4->ip_off);
  fprintf(logfile,"   | -TTL              : %d\n", ip4->ip_ttl);
  fprintf(logfile,"   | -Protocol         : %d\n", ip4->ip_p);
  fprintf(logfile,"   | -Checksum         : %u\n", ntohs(ip4->ip_sum));
  fprintf(logfile,"   | -Source Address   : %s\n", inet_ntoa(ip4->ip_src));
  fprintf(logfile,"   | -Destination Address: %s\n", inet_ntoa(ip4->ip_dst));

  if( (unsigned int)ip4->ip_p == 6 ) print_tcp_packet(hleng);
  else if( (unsigned int)ip4->ip_p == 17 ) print_udp_packet(hleng);
  else if( (unsigned int)ip4->ip_p == 1 ) print_icmp_packet(hleng);
}

void print_ipv6_header() { 
  struct ipv6_header *ip6 = (struct ipv6_header *)&buff1[14];
  char sourcAddr[INET6_ADDRSTRLEN], destAddr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(ip6->src), sourcAddr, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &(ip6->src), destAddr, INET6_ADDRSTRLEN);
  int traffic_class = (ip6->traffic_class1 << 4) | ip6->traffic_class2;

  fprintf(logfile,"IPv6 Header\n");
  fprintf(logfile,"   | -IP version       : %d\n", ip6->version);
  fprintf(logfile,"   | -Traffic class    : %d\n", traffic_class);
  fprintf(logfile,"   | -Flow label       : %d\n", ip6->flow_label);
  fprintf(logfile,"   | -Length           : %d Bytes\n", ip6->length);
  fprintf(logfile,"   | -Next header      : %d\n", ip6->next_header);
  fprintf(logfile,"   | -Hop Limit        : %d\n", ip6->hop_limit);
  fprintf(logfile,"   | -Source Address   : %s\n", sourcAddr);
  fprintf(logfile,"   | -Destination Address: %s\n", destAddr);

  if( (ip6->next_header) == 6 ) print_tcp_packet(40);
  else if( (ip6->next_header) == 17 ) print_udp_packet(40);
  else if( (ip6->next_header) == 58 ) print_icmpv6_packet();
}

void print_arp_header() {
  struct arphdr *arph = (struct arphdr *)&buff1[14];

  fprintf(logfile,"ARP Header\n");
  fprintf(logfile,"   | -Format hardware address    : %d\n", arph->ar_hrd);
  fprintf(logfile,"   | -Format of protocol address : %d\n", arph->ar_pro);
  fprintf(logfile,"   | -Length of hardware address : %d\n", arph->ar_hln);
  fprintf(logfile,"   | -Length of protocol address : %d\n", arph->ar_pln);
  fprintf(logfile,"   | -ARP opcode                 : %d\n", arph->ar_op);
}