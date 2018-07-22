#include "stdafx.h"


/*从文件中读取数据包,并建立流链表*/
STREAM_LIST * read_packet(char *path) {

	PAC packets;

	/*必要的东西，解析数据包时需要的变量*/
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

	FILE* f = fopen(path, "rb");
	if (f == NULL) {
		printf("file open error!\n");
		return NULL;
	}

	
	size_t rc;
	STREAM_LIST *sl =NULL;
	
	while (rc = fread(&packets, sizeof(PAC), (size_t) 1, f), rc != 0) {

		WinDivertHelperParsePacket(packets.packet, packets.packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, NULL);
		if (ip_header == NULL && ipv6_header == NULL)
		{
			fprintf(stderr, "warning: junk packet\n");
		}

		STREAM_LIST *header = sl;
		BOOL isIN;
		if (header == NULL) {     //不存在流链表，建立流列表
			sl = create_stream(packets, sl);
		}
		else {
			while (isIN = add2Stream(packets, *header), isIN == FALSE) {
				//STREAM_LIST 
				//create_stream(packets,sl);
				if (header->next != NULL) {
					header = header->next;
				}
				else {
					break;
				}
			}
			if (isIN == FALSE) {    //流链表中没有这个包，新建一个一条流
				sl = create_stream(packets, sl);
			}
		}
		
	}
	fclose(f);
	return sl;
	
}

/*检查一个数据包是否属于一个流,如果是，添加，如果不是，返回false*/
BOOL add2Stream(PAC p,STREAM_LIST &s) {
	/*必要的东西，解析数据包时需要的变量*/
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

	WinDivertHelperParsePacket(p.packet,p.packet_len, &ip_header,
		&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
		&udp_header, NULL, NULL);
	if (ip_header == NULL && ipv6_header == NULL)
	{
		fprintf(stderr, "warning: junk packet\n");
		return FALSE;
	}


	if (ip_header->SrcAddr == s.src_addr && tcp_header->SrcPort == s.src_port) {
		if (ip_header->DstAddr == s.dst_addr && tcp_header->DstPort == s.dst_port) {
		
			int i = s.packet_number-1;
			int j = i+1;
			for (; i >= 0; i--) {
				if (p.ID >= s.packet[i]) {
					s.packet[i+1] = p.ID;
					break;
				}
				else {
					s.packet[j] = s.packet[i];
					j--;
				}
			}
			s.packet_number += 1;

			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else if (ip_header->SrcAddr == s.dst_addr && tcp_header->SrcPort == s.dst_port) {
		if (ip_header->DstAddr == s.src_addr && tcp_header->DstPort == s.src_port) {

			int i = s.packet_number - 1;
			int j = i + 1;
			for (; i >= 0; i--) {
				if (p.ID >= s.packet[i]) {
					s.packet[i + 1] = p.ID;
					break;
				}
				else {
					s.packet[j] = s.packet[i];
					j--;
				}
			}
			s.packet_number += 1;

			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	return FALSE;
}


/*新建一条流链表,如果是第一条，就新建一条流链表，如果已有流链表，就插入进流链表的第一项*/
STREAM_LIST* create_stream(PAC p,STREAM_LIST* sl) {
	STREAM_LIST* current = sl;

	/*必要的东西，解析数据包时需要的变量*/
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;

	WinDivertHelperParsePacket(p.packet, p.packet_len, &ip_header,
		&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
		&udp_header, NULL, NULL);
	if (ip_header == NULL && ipv6_header == NULL)
	{
		fprintf(stderr, "warning: junk packet\n");
	}

	STREAM_LIST*  ne = (STREAM_LIST *)malloc(sizeof(STREAM_LIST));
	if (ne == NULL) {
		printf("malloc error !\n");
	}
	ne->dst_addr = ip_header->DstAddr;
	ne->dst_port = tcp_header->DstPort;
	ne->src_addr = ip_header->SrcAddr;
	ne->src_port = tcp_header->SrcPort;
	ne->stream_ID = ne->dst_addr + ne->src_port + ne->dst_port + ne->src_addr;    //流ID的设置
	ne->packet[0] = p.ID;
	ne->packet_number = 1;

	if (current == NULL) {     //没有流链表
		sl = ne;
		ne->next = NULL;
		return sl;
	}
	else {               //有流，插入流链表中
		STREAM_LIST * now;
		now = current;
		ne->next = now->next;
		now->next = ne;
	}
	sl = current;
	return sl;
}

/*展示流链表*/
void show_stream_list(STREAM_LIST *sl) {
	int n = 0;
	STREAM_LIST *current = sl;
	while (current != NULL) {
		n += current->packet_number;
		UINT8 *src_addr = (UINT8 *)&current->src_addr;
		UINT8 *dst_addr = (UINT8 *)&current->dst_addr;
		printf("stream_ID : %u \n", current->stream_ID);
		printf("    %u.%u.%u.%u (%u) <--> %u.%u.%u.%u (%u)  %d \n", src_addr[0], src_addr[1], src_addr[2], src_addr[3], ntohs(current->src_port),
			dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3], ntohs(current->dst_port),current->packet_number);
		//show_stream(*current);
		current = current->next;	
	}
}

/*展示一条流的数据*/
void show_stream(char *path,STREAM_LIST sl) {
	//从文件中找id对应的包拿出来就是流
	printf("stream ID is %u,  and %d 个包\n", sl.stream_ID,sl.packet_number);
	int i = 0;
	STREAM *s = select_packet_from_file(path,sl.packet,sl.packet_number);
	show_packets(s);
}

/*把一条流的包读出 到流结构体中*/
STREAM* select_packet_from_file(char *path, int *c, int packet_len) {

	PAC packets;

	FILE* f = fopen(path, "rb");
	if (f == NULL) {
		printf("open error\n");
	}
	size_t rc;
	STREAM *header = NULL;
	STREAM *end = header;

	while (rc = fread(&packets, sizeof(PAC),(size_t) 1, f), rc != 0) {
		if (packets.ID == *c) {
			STREAM *cur = (STREAM *)malloc(sizeof(STREAM));
			memcpy(cur->packet,packets.packet,MAXBUF);
			cur->packet_len = packets.packet_len;
			if (header == NULL) {
				header = cur;
				header->next = NULL;
				end = header;
				
			}
			else {
				end->next = cur;
				end = cur;
				end->next = NULL;
				
			}
			c++;
			packet_len--;
		 }
		if (packet_len <=0) {
			break;
		}
	}
	fclose(f);
	return header;
}

/*把流的数据包展示出来*/
void show_packets(STREAM *s) {

	HANDLE console;
	/*必要的东西，解析数据包时需要的变量*/
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	while (s != NULL) {
		
		WinDivertHelperParsePacket(s->packet, s->packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, NULL);
		if (ip_header == NULL && ipv6_header == NULL)
		{
			fprintf(stderr, "warning: junk packet\n");
		}
		
		if (ntohs(tcp_header->SrcPort) > ntohs(tcp_header->DstPort)) {
			SetConsoleTextAttribute(console, FOREGROUND_RED);
		}
		else {
			SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		}
		printf("%u->%u  seq:%u  ack:%u  win:%u signal:%d%d%d%d%d%d len:%d\n", ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort), 
			ntohl(tcp_header->SeqNum), ntohl(tcp_header->AckNum), ntohs(tcp_header->Window),
			tcp_header->Urg, tcp_header->Ack, tcp_header->Psh,
			tcp_header->Rst,tcp_header->Syn, tcp_header->Fin, s->packet_len);
		int ip_header_length = ip_header->HdrLength;
		int tcp_header_length = tcp_header->HdrLength;
		int i ;
		for (i = (ip_header_length + tcp_header_length)*4; i < (s->packet_len - ip_header_length - tcp_header_length); i++)
		{
			if (i % 40 == 0)
			{
				printf("\n\t");
			}
			if (isprint(s->packet[i]))
			{
				putchar(s->packet[i]);
			}
			else
			{
				putchar('.');
			}
		}
		putchar('\n');
		s = s->next;
	}
}

