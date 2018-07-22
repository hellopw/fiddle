// final_test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"




void print() {

	PURPLE();  //颜色函数
	printf("please input the operation：\n");
	printf("抓包: -fiddle \n");
	printf("阻断应用网络进程： -divert\n");
	printf("结束抓包： -stopfiddle\n");
	printf("停止阻断： -stopdivert\n");
	printf("退出： -quit\n");
	printf("输出流列表： -showlist\n");
	putchar('\n');
	WHITE();
}


int main()
{
	
	

	char s[11];    //用户最开始的命令 

	HANDLE fiddle_handle;             //线程句柄
	HANDLE divert_handle;
	unsigned int fiddle_threadid;    //线程的id
	unsigned int divert_threadid;

	int  fiddle_command = 0;         //控制线程的结束
	int  divert_command = 0;

	print();  //打印用户命令选项

	while (scanf_s("%s",s,11), s != NULL) {
		
		if (strcmp(s, "fiddle") == 0) {    //开始捕捉线程
			char filter[100];
			//int com;
			printf("please input the filter: \n");
			fgets(s, 2, stdin);     //读掉换行符
			fgets(filter, 100, stdin);
			
			//scanf("%s", filter);
			printf("fiddle :%s\n", filter);
			fiddle_command = 1;
			agrclist grclist = { filter ,fiddle_command }, *pmagrclist;
			pmagrclist = &grclist;
			fiddle_handle = (HANDLE)_beginthreadex(NULL, 0, &fiddle, pmagrclist, 0, &fiddle_threadid);
			//_beginthread(netdump, 0, pmagrclist);
			printf("fiddle is starting!\n");
			putchar('\n');
		}
		else if (strcmp(s, "stopfiddle") == 0) {   //停止捕捉线程
			if (fiddle_command == 0) {
				printf("线程没有启动！\n");
			}
			else {
				fiddle_command = 0;		 //加锁等待
				printf("请耐心等待，正在安全退出………………\n");
				WaitForSingleObject(fiddle_handle, INFINITE);  //等待线程结束
				printf("fiddle thread is end!\n");

				PURPLE();
				printf("是否要保存文件：保存 -save  不保存 -notsave\n");
				WHITE();
				char issave[8];
				scanf_s("%s", issave,8);
				if (strcmp("save", issave) == 0) {
					PURPLE();
					printf("请输入文件名： -xxx\n");
					WHITE();
					char filename[20];
					scanf_s("%s", filename,20); //缺少一个判断
					rename("tmp.pcap", filename);
					printf("success save \n");
					//rename("tmp.pcap",strcat(filename,".pcap"));
				}
				else if (strcmp("notsave", issave) == 0) {
					system("del tmp.pcap");
				}
				else {
					printf("命令无效,默认不保存\n");
					system("del tmp.pcap");
				}
				printf("stopfiddle success \n");
			}
		}
		else if (strcmp(s, "divert") == 0) {    //开始阻断应用
			char filter[100];
			printf("please input the filter: \n");
			fgets(s, 2, stdin);     //读掉换行符
			fgets(filter, 100, stdin);
		
			//scanf("%s", filter);
			printf("divert :%s\n", filter);
			divert_command = TRUE;
			agrclist grclist = { filter ,divert_command }, *pmagrclist;
			pmagrclist = &grclist;
			//_beginthread(divert, 0, pmagrclist);
			divert_handle = (HANDLE)_beginthreadex(NULL, 0, &divert, pmagrclist, 0, &divert_threadid);
			putchar('\n');

		}
		else if (strcmp(s, "stopdivert") == 0) {   //停止捕捉线程
			if (divert_command == TRUE) {
				divert_command = FALSE;
				printf("请耐心等待，正在安全退出………………\n");
				printf("divert thread is end!\n");
				WaitForSingleObject(fiddle_handle, INFINITE);  //等待线程结束
				printf("stopdivert success \n");
			}
			else {
				printf("线程没有启动\n");
			}
			
		}
		else if (strcmp(s, "quit") == 0) {   //停止所有线程，结束程序。		
			if (fiddle_command == 1) {
				fiddle_command = FALSE;
				WaitForSingleObject(fiddle_handle, INFINITE);  //等待线程结束
			}
			if (divert_command == 1) {
				divert_command = FALSE;
				WaitForSingleObject(divert_handle, INFINITE);  //等待线程结束
			}
			printf("quit\n");
			exit(0);
		}
		else if (strcmp(s, "showlist") == 0) {   //开始捕捉，并展示流列表
			char operation[15];
			PURPLE();
			printf("输入要进行的操作: 打开已保存文件 -open，打开新捕获的文件: -refiddle, 更新流：-update , 返回上一层; -back \n");
			WHITE();
			while (scanf_s("%s", operation,15), operation != NULL) {
				if (strcmp("open", operation) == 0) {
					printf("找到以下文件：");
					find_file();

					PURPLE();
					printf("输入要打开的文件名: -*.pcap ,返回上一层： -back \n");
					WHITE();
					char filename[10];

					scanf_s("%s", filename,10);
					if (strcmp("back", filename) == 0) {
						break;
					}
					else {
						STREAM_LIST * sl = read_packet(filename);
						if (sl == NULL) {
							SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
							printf("抱歉，没有找到数据流\n");
							putchar('\n');
							SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
							break;
						}
						show_stream_list(sl);
						char vorb[7];
						PURPLE();
						printf("查看某条数据流： -view, 更新数据流： -update, 返回上一层： -back \n");
						WHITE();
						while (scanf_s("%s", vorb,7), vorb != NULL) {
							if (strcmp("view", vorb) == 0) {
								int stream;
								STREAM_LIST * cur = sl;  //sl的备份
								STREAM_LIST * aim = NULL;
								printf("输入流ID： -xxxxxxxxxx \n");
								if (scanf_s("%d", &stream), stream != NULL) {
									while (cur != NULL) {
										if (cur->stream_ID == stream) {
											aim = cur;
											//free(cur);
											break;
										}
										cur = cur->next;
									}
									if (aim == NULL) {
										printf("没有这条流\n");
									}
									else {
										show_stream(filename, *aim);
										SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
									}
								}
							}
							else if (strcmp("back", vorb) == 0) {
								break;
							}
							else if (strcmp("update", vorb) == 0) {
								//start capture
								char filename[9] = "tmp.pcap";
								STREAM_LIST * sl = read_packet(filename);
								show_stream_list(sl);
								putchar('\n');
								//continue;
							}
							else {
								SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
								printf("输入无效，返回上一层\n");
								SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
								break;
							}
							PURPLE();
							printf("查看某条数据流： -view, 更新数据流： -update, 返回上一层： -back \n");
							WHITE();
						}
						putchar('\n');
					}
				}
				else if (strcmp("refiddle", operation) == 0) {
					if (fiddle_command == 1) {

					}
					else {
						char filter[100];
						//int com;
						printf("please input the filter: \n");
						fgets(s, 2, stdin);     //读掉换行符
						fgets(filter, 100, stdin);
						//scanf("%s", filter);
						printf("fiddle :%s\n", filter);
						fiddle_command = 1;
						agrclist grclist = { filter ,fiddle_command }, *pmagrclist;
						pmagrclist = &grclist;
						//_beginthread(netdump, 0, pmagrclist);
						fiddle_handle = (HANDLE)_beginthreadex(NULL, 0, &fiddle, pmagrclist, 0, &fiddle_threadid);
						printf("fiddle is starting!\n");
						putchar('\n');
					}
					//start capture
					char filename[] = "tmp.pcap";
					STREAM_LIST * sl = read_packet(filename);
					show_stream_list(sl);
					putchar('\n');
					//continue;
				}
				else if (strcmp("back", operation) == 0) {
					putchar('\n');
					break;
				}
				else if (strcmp("update", operation) == 0) {
					//start capture
					char filename[9] = "tmp.pcap";
					STREAM_LIST * sl = read_packet(filename);
					show_stream_list(sl);
					putchar('\n');
					//continue;
				}
				else {
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
					printf("输入无效，重新选择\n");
					putchar('\n');
					SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
					PURPLE();
					printf("输入要进行的操作: 打开文件 -open，或是重新捕获: -refiddle , 更新流：-update ,返回上一层： -back\n");
					WHITE();
					continue;
				}
				PURPLE();
				printf("输入要进行的操作: 打开文件 -open，或是重新捕获: -refiddle , 更新流：-update ,返回上一层： -back\n");
				WHITE();
			}
		}
		else {             //无效命令，重新输入
			PURPLE();
			printf("输入无效，重新输入\n");
			putchar('\n');
			WHITE();
		}
		print();
	}

	return 0;
}

int find_file() {      //返回找到的文件的个数
	int i = 0;
	struct _finddata_t fileinfo;
	intptr_t  fHandle;
	if ((fHandle = _findfirst("*.pcap", &fileinfo)) == -1L)
	{
		printf("当前目录下没有pcap文件\n");
		return 0;
	}
	else {
		do {
			i++;
			printf("找到文件:%s,文件大小：%d\n", fileinfo.name, fileinfo.size);
		} while (_findnext(fHandle, &fileinfo) == 0);
	}
	_findclose(fHandle);
	return i;
}



