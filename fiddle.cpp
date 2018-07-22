#include "stdafx.h"

unsigned __stdcall  fiddle(void *Argclist)
{

	char *filter_string;
	
	BOOL *end_command ;
	agrclist *pagrclist;
	pagrclist = (struct agrclist *)Argclist;
	filter_string = pagrclist->filter;
	end_command = &pagrclist->command;

	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	const char *err_str;
	LARGE_INTEGER base, freq;

	

	handle = WinDivertOpen(filter_string, WINDIVERT_LAYER_NETWORK, priority,
		WINDIVERT_FLAG_SNIFF);
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

	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192))
	{
		fprintf(stderr, "error: failed to set packet queue length (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))
	{
		fprintf(stderr, "error: failed to set packet queue time (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&base);

	
	/*FILE *f;
	errno_t err;
	if ((err = fopen_s(&f, "tmp.pcap", "w+b")) != 0) {
		printf("file open error!\n");
		WinDivertClose(handle);
		_endthreadex(0);
	}*/
	FILE *f = fopen("tmp.pcap", "w+b");
	if (f == NULL) {
		printf("file open error!\n");
		return NULL;
	}

		int packet_id = 0;
		while (*end_command)
		{
			if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
			{
				fprintf(stderr, "warning: failed to read packet (%d)\n",
					GetLastError());
				continue;
			}


			WinDivertHelperParsePacket(packet, packet_len, &ip_header,
				&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
				&udp_header, NULL, NULL);
			if (ip_header == NULL && ipv6_header == NULL)
			{
				fprintf(stderr, "warning: junk packet\n");
			}

			PAC  packets;
			if (ip_header != NULL) {
				if (tcp_header != NULL || tcp_header != NULL) {
					memcpy(packets.packet, packet, MAXBUF);
					packets.ID = packet_id;
					packets.packet_len = packet_len;
					fwrite(&packets, sizeof(PAC), 1, f);
					packet_id++;
				}
			}
		}
	
	fclose(f);
	WinDivertClose(handle);
	_endthreadex(0);    
	
	return 0;
}

