#include "stdafx.h"
pcap_if* getdev() {

	pcap_if_t* alldevs;
	pcap_if *d = (pcap_if*)malloc(sizeof(pcap_if*));
	char errbuf[PCAP_ERRBUF_SIZE];
	int inum;
	int i = 0;

	/* 获得设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return NULL;
	}

	/* 跳转到已选设备 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	//还没有释放alldev的内存空间
	pcap_freealldevs(alldevs);

	return d;
}

ip_address get_ip(pcap_if *d) {
	ip_address  ipv4 = { 0,0,0,0 };


	/*pcap_lookupnet(d->name, &net_ip, &net_mask, errbuf);

	net_ip_address.s_addr = net_ip;
	net_ip_string = inet_ntoa(net_ip_address);//format
	printf("网络地址: %s \n", net_ip_string);

	net_mask_address.s_addr = net_mask;
	net_mask_string = inet_ntoa(net_mask_address);//format
	printf("子网掩码: %s \n", net_mask_string);*/
	pcap_addr_t *a;
	a = d->addresses;

	for (; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr) {
				u_char *p = (u_char*) &((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
				ipv4 = { p[0],p[1],p[2],p[3] };
				return ipv4;
			}
			//printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
		default:
			/* 未知 */
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	return ipv4;

}

bool strcmp_ip(ip_address i1, ip_address i2) {
	if (i1.byte1 == i2.byte1 && i1.byte2 == i2.byte2 && i1.byte3 == i2.byte3 && i1.byte4 == i2.byte4) {
		return true;
	}
	else return false;

}