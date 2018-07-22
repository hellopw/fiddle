#include "stdafx.h"

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* 获得IP数据包头部的位置 */
	ih = (ip_header *)(pkt_data +
		14); //以太网头部长度为14

			 /* 获得UDP首部的位置 */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* 将网络字节序列转换成主机字节序列 */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	//打印ip和端口  4元祖
	if (strcmp_ip(ih->saddr, ipv4) || strcmp_ip(ih->daddr, ipv4)) {    //只输出进出本机的数据包
																	   /* 打印数据包的时间戳和长度 */
		printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
		printf("%d.%d.%d.%d  %d -> %d.%d.%d.%d  %d\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport);
	}
	else {
		//printf("\n");
	}


}