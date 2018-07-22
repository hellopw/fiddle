#pragma once
#include "stdafx.h"

typedef struct
{
	unsigned char packet[1500];    //一个完整的数据包，包含包头，包数据
	int packet_len;   //数据包的有效长度   在fread时会用到
	int ID;        //包的ID，按捕获时间赋值，用来构造包数组
} PAC;

struct Stream_list          //数据流的链表
{
	UINT32 src_addr;
	UINT32 dst_addr;
	UINT16 src_port;
	UINT16 dst_port;   //ip和端口作为流的第一标识

	int stream_ID;  //ID作为流的第二标识  因为相同的ip和端口有可能第二次建立连接。

	//STREAM stream;     //包链表  链表中存放包ID  数组不方便插入
	//PAC packet[135];
	int packet[200];     //包数组   用数据包的id来标识可以省空间。
	int packet_number;       //包的数量
	
	struct Stream_list *next;
	//PAC packet[100]
};
typedef struct Stream_list STREAM_LIST;

struct Stream      //数据包的链表   构成  数据流
{
	unsigned char packet[1500];
	int packet_len;
	struct Stream *next;
	
};
typedef struct Stream STREAM;