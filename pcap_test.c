#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[6];/* destination ethernet address */
	u_int8_t  ether_shost[6];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
}eth;

typedef struct libnet_ipv4_hdr
{
	u_int8_t ip_hl : 4,      /* header length */
		ip_v : 4;         /* version */

	u_int8_t ip_tos;       /* type of service */
#
	u_int16_t ip_len;         /* total length */
	u_int16_t ip_id;          /* identification */
	u_int16_t ip_off;

	u_int8_t ip_ttl;          /* time to live */
	u_int8_t ip_p;            /* protocol */
	u_int16_t ip_sum;         /* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
}ip;

typedef struct libnet_tcp_hdr
{
	u_int16_t th_sport;       /* source port */
	u_int16_t th_dport;       /* destination port */
	u_int32_t th_seq;          /* sequence number */
	u_int32_t th_ack;          /* acknowledgement number */

	u_int8_t th_x2 : 4,         /* (unused) */
		th_off : 4;        /* data offset */

	u_int8_t  th_flags;       /* control flags */

	u_int16_t th_win;         /* window */
	u_int16_t th_sum;         /* checksum */
	u_int16_t th_urp;         /* urgent pointer */
}tcp;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		eth* ethhd;
		ip* iphd;
		tcp* tcphd;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		ethhd = (eth* )packet;
		if (ntohs(ethhd->ether_type) != 0x0800) {
			printf("Layer3 is not IP");
			exit(1);
		}
		packet += 14;

		iphd = (ip* )packet;
		if (iphd->ip_p != 0x06) {
			printf("Layer4 is not TCP");
			exit(1);
		}
		packet += (iphd->ip_hl) * 4;

		tcphd = (tcp* )packet;

		packet += (tcphd->th_off) * 4;
		
		printf("Ethernet: %x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x \n"
			, ethhd->ether_dhost[0], ethhd->ether_dhost[1], ethhd->ether_dhost[2], ethhd->ether_dhost[3], ethhd->ether_dhost[4], ethhd->ether_dhost[5]
			, ethhd->ether_shost[0], ethhd->ether_shost[1], ethhd->ether_shost[2], ethhd->ether_shost[3], ethhd->ether_shost[4], ethhd->ether_shost[5]);
		
		printf("IP: %d.%d.%d.%d -> %d.%d.%d.%d\n",
			(u_char)(iphd->ip_src.s_addr), (u_char)(iphd->ip_src.s_addr >> 8), (u_char)(iphd->ip_src.s_addr >>16),(iphd->ip_src.s_addr) >> 24,
			(u_char)(iphd->ip_dst.s_addr), (u_char)(iphd->ip_dst.s_addr >> 8), (u_char)(iphd->ip_dst.s_addr>>16), (iphd->ip_dst.s_addr) >> 24);

		printf("TCP: %d -> %d\n", ntohs(tcphd->th_sport), ntohs(tcphd->th_dport));
		
		unsigned char* data = (unsigned char*)packet;

		if (header->caplen == 14 + (iphd->ip_hl) * 4 + (tcphd->th_off) * 4) {
			printf("DATA: 00 00 00 00 00 00 00 00");
			printf("\n==============================================\n");
			continue;
		}
			printf("DATA: ");
			for (int i = 0; i < 8; i++)
			{
				printf("%02X ", *data);
				data += 1;
			}
		

		printf("\n==============================================\n");
		
	}

	pcap_close(pcap);
}
