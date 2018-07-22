// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include <windivert.h>
#include "divert.h"
#include "packet_stream.h"

#include <process.h>         //多线程

#include <pcap.h>
#include <direct.h>          //处理文件路径，获取文件夹下的文件


#define MAXBUF 1500

struct agrclist {         //线程传参结构体   一个是过滤线程的过滤字符串  一个是线程的停止和启动
	char *filter;
	BOOL &command;
};

#define PURPLE() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE);
#define WHITE() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#define RED() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED );
#define BLUE() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),  FOREGROUND_BLUE);
#define GREEN() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN );
#define CYAN() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE),  FOREGROUND_GREEN | FOREGROUND_BLUE);
#define YELLOW() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_RED);


unsigned __stdcall  fiddle(void *argv);    //抓包
unsigned __stdcall divert(void *argv);      //阻断
STREAM_LIST * read_packet(char *packet);   //将数据包读出到流中     
BOOL add2Stream(PAC p, STREAM_LIST &s);       //判断一个包是否属于一条流
STREAM_LIST* create_stream(PAC p, STREAM_LIST* sl);     //创建一条流链表
void show_stream_list(STREAM_LIST *sl);         //展示流链表一条流完整的数据
void show_stream(char *path,STREAM_LIST sl);       //展示
STREAM * select_packet_from_file(char *path,int *c, int x);      //从文件中选择包
void show_packets(STREAM *s);                //展示一个数据包
int find_file();

// TODO: 在此处引用程序需要的其他头文件
