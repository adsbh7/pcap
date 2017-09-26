#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <libnet/libnet-headers.h>

 int main(int argc, char *argv[])
 {
        int i,len;
      	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 

        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return -1;
        }

        while(1)
        {
                struct pcap_pkthdr* header;
                const u_char* packet;
                int res = pcap_next_ex(handle, &header, &packet); // packet capture
		uint16_t ethertype;
		uint8_t ip_protocol;

		if(res == 0) continue;
                else if(res > 0)
                {
                     //   struct ether_header * ethhdr; 
                      //  struct ip * iphdr;
		//	struct tcphdr * tcphdr;
			
			struct libnet_ethernet_hdr * ethhdr;
			struct libnet_ipv4_hdr * iphdr;
			struct libnet_tcp_hdr *tcphdr;
	
			ethhdr = (struct libnet_ethernet_hdr *)packet;
					
                        printf("------------Packet-------------\n"); 
			printf("<Ethernet>\n");
			printf("Src MAC : ");
                        for(i=0;i<6;i++)
                        {
                                printf("%02X", ethhdr->ether_shost[i]);
                                if(i==5) break;
                                printf(":");
                        }	

			printf("\n");
			printf("Dest MAC : ");
                        for(i=0;i<6;i++)
                        {
                                printf("%02X", ethhdr->ether_dhost[i]);
                                if(i==5) break;
                                printf(":");
                        }
			
			//printf("\nethertype : %x\n",ethhdr->ether_type);	

			ethertype = ntohs(ethhdr->ether_type);
			
			if(ethertype == 0x0800)
			{
				iphdr = (struct libnet_ipv4_hdr *)(packet + 14); // ethernet header 크기만큼 이동

				printf("\n\n<IP>\n");

				printf("Src IP: %s\n", inet_ntoa(iphdr->ip_src));
				printf("Dest IP: %s\n", inet_ntoa(iphdr->ip_dst));

			}

			else printf("Not IP Packet\n");

			ip_protocol = iphdr->ip_p;

			//printf("pro : %x\n",ip_protocol);

			if(ip_protocol == 0x6) // tcp인 경우
			{
				tcphdr = (struct libnet_tcp_hdr *)(packet + 14 + iphdr->ip_hl*4);

				printf("\n<TCP>\n");
				printf("Src PORT: %d \n", ntohs(tcphdr->th_sport));
	                        printf("Dest PORT: %d \n", ntohs(tcphdr->th_dport));
				len = iphdr->ip_len - iphdr->ip_hl*4 - tcphdr->th_off*4;
				packet = packet + 14 + iphdr->ip_hl*4 + tcphdr->th_off*4;

				printf("\n<DATA>\n");
				
				if(len != 0)
				{
					if(len > 16) len=16;
					for(i=0;i<len;i++)
					{
						printf("%02X ",*(packet+i) );
					
					}
					printf("\n");
				}

				else printf("No DATA\n");

			}

			else printf("Not TCP Packet\n");

                        printf("\n");
                }

                else if (res == -1 || res == -2) break;

        }

        pcap_close(handle);
        return 0;
 }

