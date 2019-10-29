#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sniffer.h"
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0;
struct sockaddr_in source,dest;
char hex[2];
void snif_open_log_file()
{
	logfile=fopen("log.txt","w");
	if(logfile == NULL){
		vcSnifPrintf("Unable to create file.");
	}
    return;
}
int main()
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;
	int i,j;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

    	snif_open_log_file();

	//Initialise Winsock
	vcSnifPrintf("Initialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0){
		vcSnifPrintf("WSAStartup() failed.\n");
		return 1;
	}
	//vcSnifPrintf("Initialised");
	//Create a RAW Socket
	vcSnifPrintf("Creating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET){
		vcSnifPrintf("Failed to create raw socket.");
		return 1;
	}
	//vcSnifPrintf("Created.");

	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR){
		vcSnifPrintf("Error : %d",WSAGetLastError());
		return 1;
	}
	vcSnifPrintf("Host name : %s",hostname);

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	vcSnifPrintf("Available Network Interfaces :");
	if (local == NULL){
		vcSnifPrintf("Error : %d.\n",WSAGetLastError());
		return 1;
	}
	for (i = 0; local->h_addr_list[i] != 0; ++i){
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		vcSnifPrintf("Interface Number : %d Address : %s",i,inet_ntoa(addr));
	}
	vcSnifPrintf("Enter the interface number you would like to sniff : ");
	scanf("%d",&in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	vcSnifPrintf("Binding socket to local system and port 0 ...");
	vcSnifPrintf("sAddr:%X",dest.sin_addr.s_addr);
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR){
		vcSnifPrintf("bind(%s) failed.", inet_ntoa(addr));
		return 1;
	}
	vcSnifPrintf("Binding successful");

	j=1;
	vcSnifPrintf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR){
		vcSnifPrintf("WSAIoctl() failed.");
		return 1;
	}

	vcSnifPrintf("Socket set.");

	StartSniffing(sniffer);
	closesocket(sniffer);
	WSACleanup();
    	return 0;
}
void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;

	if (Buffer == NULL){
		vcSnifPrintf("malloc() failed.");
		return;
	}

	do{
		mangobyte = recvfrom(sniffer , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can
		if(mangobyte > 0){
			ProcessPacket(Buffer, mangobyte);
		}else{
			vcSnifPrintf( "recvfrom() failed.");
		}
	}
	while (mangobyte > 0);
	free(Buffer);
}
void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;
	++total;

	switch (iphdr->ip_protocol){
		case ICMP_Protocol:{
			++icmp;
			PrintIcmpPacket(Buffer,Size);
			break;
		}
		case IGMP_Protocol:{
			++igmp;
			break;
		}
		case TCP_Protocol:{
			++tcp;
			PrintTcpPacket(Buffer,Size);
			break;
		}
		case UDP_Protocol:{
			++udp;
			PrintUdpPacket(Buffer,Size);
			break;
		}
		default:{ //Some Other Protocol like ARP etc.
			++others;
			break;
		}
	}
	vcSnifDump("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r",tcp,udp,icmp,igmp,others,total);
}
void PrintIcmpPacket(char* Buffer , int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;
	icmpheader=(ICMP_HDR*)(Buffer+iphdrlen);
	fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer);
	fprintf(logfile,"\n");
	fprintf(logfile,"ICMP Header\n");
	fprintf(logfile," |-Type : %d",(unsigned int)(icmpheader->type));
	if((unsigned int)(icmpheader->type)==11){
		fprintf(logfile," (TTL Expired)\n");
	}else if((unsigned int)(icmpheader->type)==0){
		fprintf(logfile," (ICMP Echo Reply)\n");
	}
	fprintf(logfile," |-Code : %d\n",(unsigned int)(icmpheader->code));
	fprintf(logfile," |-Checksum : %d\n",ntohs(icmpheader->checksum));
	fprintf(logfile," |-ID : %d\n",ntohs(icmpheader->id));
	fprintf(logfile," |-Sequence : %d\n",ntohs(icmpheader->seq));
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
	fprintf(logfile,"UDP Header\n");
	PrintData(Buffer+iphdrlen,sizeof(ICMP_HDR));
	fprintf(logfile,"Data Payload\n");
	PrintData(Buffer+iphdrlen+sizeof(ICMP_HDR) , (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len*4));
	fprintf(logfile,"\n###########################################################");
}
void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;
	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;
	tcpheader=(TCP_HDR*)(Buffer+iphdrlen);
	fprintf(logfile,"\n\n***********************TCP Packet*************************\n");
	PrintIpHeader( Buffer );
	fprintf(logfile,"\n");
	fprintf(logfile,"TCP Header\n");
	fprintf(logfile," |-Source Port : %u\n",ntohs(tcpheader->source_port));
	fprintf(logfile," |-Destination Port : %u\n",ntohs(tcpheader->dest_port));
	fprintf(logfile," |-Sequence Number : %u\n",ntohl(tcpheader->sequence));
	fprintf(logfile," |-Acknowledge Number : %u\n",ntohl(tcpheader->acknowledge));
	fprintf(logfile," |-Header Length : %d DWORDS or %d BYTES\n"
	,(unsigned int)tcpheader->data_offset,(unsigned int)tcpheader->data_offset*4);
	fprintf(logfile," |-CWR Flag : %d\n",(unsigned int)tcpheader->cwr);
	fprintf(logfile," |-ECN Flag : %d\n",(unsigned int)tcpheader->ecn);
	fprintf(logfile," |-Urgent Flag : %d\n",(unsigned int)tcpheader->urg);
	fprintf(logfile," |-Acknowledgement Flag : %d\n",(unsigned int)tcpheader->ack);
	fprintf(logfile," |-Push Flag : %d\n",(unsigned int)tcpheader->psh);
	fprintf(logfile," |-Reset Flag : %d\n",(unsigned int)tcpheader->rst);
	fprintf(logfile," |-Synchronise Flag : %d\n",(unsigned int)tcpheader->syn);
	fprintf(logfile," |-Finish Flag : %d\n",(unsigned int)tcpheader->fin);
	fprintf(logfile," |-Window : %d\n",ntohs(tcpheader->window));
	fprintf(logfile," |-Checksum : %d\n",ntohs(tcpheader->checksum));
	fprintf(logfile," |-Urgent Pointer : %d\n",tcpheader->urgent_pointer);
	fprintf(logfile,"\n");
	fprintf(logfile," DATA Dump ");
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
	fprintf(logfile,"TCP Header\n");
	PrintData(Buffer+iphdrlen,tcpheader->data_offset*4);
	fprintf(logfile,"Data Payload\n");
	PrintData(Buffer+iphdrlen+tcpheader->data_offset*4,
		(Size-tcpheader->data_offset*4-iphdr->ip_header_len*4));
	fprintf(logfile,"\n###########################################################");
}
void PrintUdpPacket(char *Buffer,int Size)
{
	int i = 0;
	unsigned short iphdrlen;
	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;
	udpheader = (UDP_HDR *)(Buffer + iphdrlen);
	fprintf(logfile,"\n\n***********************UDP Packet*************************\n");
	PrintIpHeader(Buffer);
	fprintf(logfile,"\nUDP Header\n");
	fprintf(logfile," |-Source Port : %d\n",ntohs(udpheader->source_port));
	fprintf(logfile," |-Destination Port : %d\n",ntohs(udpheader->dest_port));
	fprintf(logfile," |-UDP Length : %d\n",ntohs(udpheader->udp_length));
	fprintf(logfile," |-UDP Checksum : %d\n",ntohs(udpheader->udp_checksum));

	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	PrintData(Buffer,iphdrlen);
	fprintf(logfile,"UDP Header\n");
	PrintData(Buffer+iphdrlen,sizeof(UDP_HDR));
	fprintf(logfile,"Data Payload\n");
	PrintData(Buffer+iphdrlen+sizeof(UDP_HDR) ,(Size - sizeof(UDP_HDR) - iphdr->ip_header_len*4));
	fprintf(logfile,"\n###########################################################");

}
void PrintIpHeader (char* Buffer )
{
	unsigned short iphdrlen;
	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile," |-IP Version : %d\n",(unsigned int)iphdr->ip_version);
	fprintf(logfile," |-IP Header Length : %d DWORDS or %d Bytes\n",(unsigned int)iphdr->ip_header_len,((unsigned int)(iphdr->ip_header_len))*4);
	fprintf(logfile," |-Type Of Service : %d\n",(unsigned int)iphdr->ip_tos);
	fprintf(logfile," |-IP Total Length : %d Bytes(Size of Packet)\n",ntohs(iphdr->ip_total_length));
	fprintf(logfile," |-Identification : %d\n",ntohs(iphdr->ip_id));
	fprintf(logfile," |-Reserved ZERO Field : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	fprintf(logfile," |-Dont Fragment Field : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	fprintf(logfile," |-More Fragment Field : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(logfile," |-TTL : %d\n",(unsigned int)iphdr->ip_ttl);
	fprintf(logfile," |-Protocol : %d\n",(unsigned int)iphdr->ip_protocol);
	fprintf(logfile," |-Checksum : %d\n",ntohs(iphdr->ip_checksum));
	fprintf(logfile," |-Source IP : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile," |-Destination IP : %s\n",inet_ntoa(dest.sin_addr));
}
void PrintData (char* data , int Size)
{
	char a , line[17] , c;
	int j,i;

	//loop over each character and print
	for(i=0 ; i < Size ; i++){
		c = data[i];

		//Print the hex value for every character , with a space. Important to make unsigned
		fprintf(logfile," %.2x", (unsigned char) c);
		//Add the character to data line. Important to make unsigned
		a = ( c >=32 && c <=128) ? (unsigned char) c : '.';
		line[i%16] = a;
		//if last character of a line , then print the line - 16 characters in 1 line
		if( (i!=0 && (i+1)%16==0) || i == Size - 1){
			line[i%16 + 1] = '\0';
			//print a big gap of 10 characters between hex and characters
			fprintf(logfile ,"          ");
			//Print additional spaces for last lines which might be less than 16 characters in length
			for( j = strlen(line) ; j < 16; j++){
				fprintf(logfile , "   ");
			}
			fprintf(logfile , "%s \n" , line);
		}
	}
	fprintf(logfile , "\n");

}
