#include "stdafx.h"



unsigned __stdcall divert(void *Argclist) {

	char *filter_string;

	BOOL *end_command;
	agrclist *pagrclist;
	pagrclist = (struct agrclist *)Argclist;
	filter_string = pagrclist->filter;
	end_command = &pagrclist->command;

	HANDLE handle;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	const char *err_str;

	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	UINT8 dnr0[sizeof(ICMPPACKET) + 0x0F * sizeof(UINT32) + 8 + 1];
	PICMPPACKET dnr = (PICMPPACKET)dnr0;

	TCPV6PACKET resetv6_0;
	PTCPV6PACKET resetv6 = &resetv6_0;
	UINT8 dnrv6_0[sizeof(ICMPV6PACKET) + sizeof(WINDIVERT_IPV6HDR) +
		sizeof(WINDIVERT_TCPHDR)];
	PICMPV6PACKET dnrv6 = (PICMPV6PACKET)dnrv6_0;

	// 初始化注入的包
	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketIpIcmpInit(dnr);
	dnr->icmp.Type = 3;         
	dnr->icmp.Code = 3;         
	PacketIpv6TcpInit(resetv6);
	resetv6->tcp.Rst = 1;
	resetv6->tcp.Ack = 1;
	PacketIpv6Icmpv6Init(dnrv6);
	dnrv6->ipv6.Length = htons(sizeof(WINDIVERT_ICMPV6HDR) + 4 +
		sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_TCPHDR));
	dnrv6->icmpv6.Type = 1;     
	dnrv6->icmpv6.Code = 4;     

	handle = WinDivertOpen(filter_string, WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCheckFilter(filter_string, WINDIVERT_LAYER_NETWORK,
				&err_str, NULL))
		{
			fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	
	/*FILE * f;
	errno_t err;
	err = fopen_s(&f,"divert.txt", "a");
	if (err != 0) {
		printf("file open error!\n");
		WinDivertClose(handle);
		_endthreadex(0);

	}*/
	FILE * f = fopen("divert.txt", "a");
	if (f == NULL) {
		printf("file open error!\n");
		return NULL;
	}
	
	while (*end_command)
	{
		
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, &payload_len);
		if (ip_header == NULL && ipv6_header == NULL)
		{
			continue;
		}

		
		fputs("DIVERT ", f);
		if (ip_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			fprintf(f, "ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}
		if (ipv6_header != NULL)
		{
			UINT16 *src_addr = (UINT16 *)&ipv6_header->SrcAddr;
			UINT16 *dst_addr = (UINT16 *)&ipv6_header->DstAddr;
			fputs("ipv6.SrcAddr=", f);
			for (i = 0; i < 8; i++)
			{
				fprintf(f, "%x%c", ntohs(src_addr[i]), (i == 7 ? ' ' : ':'));
			}
			fputs(" ipv6.DstAddr=", f);
			for (i = 0; i < 8; i++)
			{
				fprintf(f, "%x%c", ntohs(dst_addr[i]), (i == 7 ? ' ' : ':'));
			}
			//putchar(' ');
			fputc(' ', f);
		}
		if (icmp_header != NULL)
		{
			fprintf(f, "icmp.Type=%u icmp.Code=%u ",
				icmp_header->Type, icmp_header->Code);
		}
		if (icmpv6_header != NULL)
		{
			fprintf(f, "icmpv6.Type=%u icmpv6.Code=%u ",
				icmpv6_header->Type, icmpv6_header->Code);
		}
		if (tcp_header != NULL)
		{
			fprintf(f, "tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=",
				ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
			if (tcp_header->Fin)
			{
				fputs("[FIN]", f);
			}
			if (tcp_header->Rst)
			{
				fputs("[RST]", f);
			}
			if (tcp_header->Urg)
			{
				fputs("[URG]", f);
			}
			if (tcp_header->Syn)
			{
				fputs("[SYN]", f);
			}
			if (tcp_header->Psh)
			{
				fputs("[PSH]", f);
			}
			if (tcp_header->Ack)
			{
				fputs("[ACK]", f);
			}
			putchar(' ');

			if (ip_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
			{
				reset->ip.SrcAddr = ip_header->DstAddr;
				reset->ip.DstAddr = ip_header->SrcAddr;
				reset->tcp.SrcPort = tcp_header->DstPort;
				reset->tcp.DstPort = tcp_header->SrcPort;
				reset->tcp.SeqNum =
					(tcp_header->Ack ? tcp_header->AckNum : 0);
				reset->tcp.AckNum =
					(tcp_header->Syn ?
						htonl(ntohl(tcp_header->SeqNum) + 1) :
						htonl(ntohl(tcp_header->SeqNum) + payload_len));

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				WinDivertHelperCalcChecksums((PVOID)reset, sizeof(TCPPACKET),
					&send_addr, 0);
				if (!WinDivertSend(handle, (PVOID)reset, sizeof(TCPPACKET),
					&send_addr, NULL))
				{
					fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
						GetLastError());
				}
			}

			if (ipv6_header != NULL && !tcp_header->Rst && !tcp_header->Fin)
			{
				memcpy(resetv6->ipv6.SrcAddr, ipv6_header->DstAddr,
					sizeof(resetv6->ipv6.SrcAddr));
				memcpy(resetv6->ipv6.DstAddr, ipv6_header->SrcAddr,
					sizeof(resetv6->ipv6.DstAddr));
				resetv6->tcp.SrcPort = tcp_header->DstPort;
				resetv6->tcp.DstPort = tcp_header->SrcPort;
				resetv6->tcp.SeqNum =
					(tcp_header->Ack ? tcp_header->AckNum : 0);
				resetv6->tcp.AckNum =
					(tcp_header->Syn ?
						htonl(ntohl(tcp_header->SeqNum) + 1) :
						htonl(ntohl(tcp_header->SeqNum) + payload_len));

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				WinDivertHelperCalcChecksums((PVOID)resetv6,
					sizeof(TCPV6PACKET), &send_addr, 0);
				if (!WinDivertSend(handle, (PVOID)resetv6, sizeof(TCPV6PACKET),
					&send_addr, NULL))
				{
					fprintf(stderr, "warning: failed to send TCP (IPV6) "
						"reset (%d)\n", GetLastError());
				}
			}
		}
		if (udp_header != NULL)
		{
			fprintf(f, "udp.SrcPort=%u udp.DstPort=%u ",
				ntohs(udp_header->SrcPort), ntohs(udp_header->DstPort));
			if (ip_header != NULL)
			{
				UINT icmp_length = ip_header->HdrLength * sizeof(UINT32) + 8;
				memcpy(dnr->data, ip_header, icmp_length);
				icmp_length += sizeof(ICMPPACKET);
				dnr->ip.Length = htons((UINT16)icmp_length);
				dnr->ip.SrcAddr = ip_header->DstAddr;
				dnr->ip.DstAddr = ip_header->SrcAddr;

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				WinDivertHelperCalcChecksums((PVOID)dnr, icmp_length,
					&send_addr, 0);
				if (!WinDivertSend(handle, (PVOID)dnr, icmp_length, &send_addr,
					NULL))
				{
					fprintf(stderr, "warning: failed to send ICMP message "
						"(%d)\n", GetLastError());
				}
			}

			if (ipv6_header != NULL)
			{
				UINT icmpv6_length = sizeof(WINDIVERT_IPV6HDR) +
					sizeof(WINDIVERT_TCPHDR);
				memcpy(dnrv6->data, ipv6_header, icmpv6_length);
				icmpv6_length += sizeof(ICMPV6PACKET);
				memcpy(dnrv6->ipv6.SrcAddr, ipv6_header->DstAddr,
					sizeof(dnrv6->ipv6.SrcAddr));
				memcpy(dnrv6->ipv6.DstAddr, ipv6_header->SrcAddr,
					sizeof(dnrv6->ipv6.DstAddr));

				memcpy(&send_addr, &recv_addr, sizeof(send_addr));
				send_addr.Direction = !recv_addr.Direction;
				WinDivertHelperCalcChecksums((PVOID)dnrv6, icmpv6_length,
					&send_addr, 0);
				if (!WinDivertSend(handle, (PVOID)dnrv6, icmpv6_length,
					&send_addr, NULL))
				{
					fprintf(stderr, "warning: failed to send ICMPv6 message "
						"(%d)\n", GetLastError());
				}
			}
		}
		fputc('\n', f);
	}
	fclose(f);
	WinDivertClose(handle);
	_endthreadex(0);
	return 0;

}

/*
* Initialize a PACKET.
*/
static void PacketIpInit(PWINDIVERT_IPHDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);
	packet->TTL = 64;
}

/*
* Initialize a TCPPACKET.
*/
static void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an ICMPPACKET.
*/
static void PacketIpIcmpInit(PICMPPACKET packet)
{
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}

/*
* Initialize a PACKETV6.
*/
static void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}

/*
* Initialize a TCPV6PACKET.
*/
static void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an ICMP PACKET.
*/
static void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}
