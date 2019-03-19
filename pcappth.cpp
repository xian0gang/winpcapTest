#include "pcappth.h"
#include <QFile>

extern int net_index;

pcapPth::pcapPth(QObject *parent) : QThread(parent)
{
//    yuv_index = 0;
    qq = false;
}


void pcapPth::run()
{
    FILE *fp;
    pcap_if_t *alldevs;
    pcap_if_t *d;
//    int inum;
    int i=0;
    pcap_t *adhandle;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;
    struct tm *ltime;
    char timestr[16];
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and udp and port 5000";
    struct bpf_program fcode;

    unsigned char yuv_index;


    /* 获得设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
//        fqDebug(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印列表 */
    for(d=alldevs; d; d=d->next)
    {
        qDebug("%d. %s", ++i, d->name);
        if (d->description)
            qDebug(" (%s)\n", d->description);
        else
            qDebug(" (No description available)\n");
    }

    int inum = net_index;
    /* 跳转到已选设备 */
    for(d=alldevs, i=0; i< inum-1 ; d=d->next, i++);

    /* 打开适配器 */
    if ( (adhandle= pcap_open(d->name,  // 设备名
                          65536,     // 要捕捉的数据包的部分
                          // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                          PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
                          1000,      // 读取超时时间
                          NULL,      // 远程机器验证
                          errbuf     // 错误缓冲池
                         ) ) == NULL)
    {
    //                fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        qDebug(" pcap_open");
        pcap_freealldevs(alldevs);
    //                return;
    }

    /* 检查数据链路层，为了简单，我们只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        //                 fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
         /* 释放设备列表 */
         pcap_freealldevs(alldevs);
        //                 return;
         qDebug(" pcap_datalink");
    }

    if(d->addresses != NULL)
         /* 获得接口第一个地址的掩码 */
         netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
         /* 如果接口没有地址，那么我们假设一个C类的掩码 */
         netmask=0xffffff;

 //编译过滤器
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
//                     fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
         /* 释放设备列表 */
         pcap_freealldevs(alldevs);
         qDebug(" Unable to compile the packet filter. Check the syntax");
//                     return -1;
    }

     //设置过滤器
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
//                     fprintf(stderr,"\nError setting the filter.\n");
         /* 释放设备列表 */
         pcap_freealldevs(alldevs);
          qDebug(" Error setting the filter");
//                     return -1;
    }

    qDebug("\nlistening on %s...\n", d->description);

     /* 释放设备列表 */
    pcap_freealldevs(alldevs);

     /* 开始捕捉 */
//                 pcap_loop(adhandle, 0, packet_handler, NULL);
     /* 获取数据包 */
    int res;
    unsigned short pro_c = 0;
    bool first_idx = true;
    QFile *tempFile = new QFile;
    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0)
    {
         if(res == 0)
         {
             qDebug("timeout");
             /* 超时时间到 */
             continue;
         }

//         struct tm *ltime;
//         char timestr[16];
         ip_header *ih;
         udp_header *uh;
         u_int ip_len;
         u_short sport,dport;
//         time_t local_tv_sec;

         /* 将时间戳转换成可识别的格式 */
//         local_tv_sec = header->ts.tv_sec;
//         ltime=localtime(&local_tv_sec);
//         strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

         /* 打印数据包的时间戳和长度 */
//         qDebug("%s.%.6ld len:%d ", timestr, header->ts.tv_usec, header->len);

         /* 获得IP数据包头部的位置 */
         ih = (ip_header *) (pkt_data + 14); //以太网头部长度

         /* 获得UDP首部的位置 */
         ip_len = (ih->ver_ihl & 0xf) * 4;
         uh = (udp_header *) ((u_char*)ih + ip_len);

         /* 将网络字节序列转换成主机字节序列 */
         sport = ntohs( uh->sport );
         dport = ntohs( uh->dport );

         if(dport != 5000)
         {
            continue;
         }

            yuv_index = *(pkt_data + 14 + ip_len + 8);
            emit send_index(yuv_index);
            unsigned char e = *(pkt_data + 14 + ip_len + 9);
            unsigned char d = *(pkt_data + 14 + ip_len + 10);

            short c = d * 255 + e;
//            qDebug("e:%d, d:%d", e, d);
//            qDebug("index:%d, idx:%d", yuv_index, c);
            emit send_idx(int(c));
             char yuv_data[1024];
            memcpy(yuv_data, (pkt_data + 14 + ip_len + 11), 1024);

            if(first_idx)
            {
                if(c == 0)
                {
                    first_idx = false;
                }
                else
                {
                    continue;
                }
            }
            if(c == 0)
            {
                tempFile->close();
                QString str;
                str = QString::number(yuv_index, 10);
                tempFile->setFileName(str + ".yuv");
                if(!tempFile->open(QIODevice::WriteOnly))
                {
                    qDebug("open falied");
                }
                pro_c = 0;
                int len = tempFile->write(yuv_data, 1024);
//                qDebug("len:%d", len);
                pro_c = c + 1;
                continue;
            }


            for(int i = 0; i < c - pro_c; i++)
            {
//                qDebug("write zero");
                const char zero_data[1024] = { 0 };
                int len = tempFile->write(zero_data, 1024);
//                qDebug("len:%d", len);
            }

            pro_c = c + 1;
            int len = tempFile->write(yuv_data, 1024);
//            qDebug("len:%d", len);

            if(c >= 4048)
            {
                tempFile->close();
            }
//         }
            if(qq)
            {
                tempFile->close();
                return;
            }
    }
}

void pcapPth::quitt()
{
    qq = true;
}


