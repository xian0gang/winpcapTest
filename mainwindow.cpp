#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QFile>

#include <QTime>

int net_index;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    show_net();
    QTime timedebuge;//声明一个时钟对象
    timedebuge.start();//开始计时

//    QFile *tempFile = new QFile;
//    tempFile->close();
//    int yuv_index = 111;
//    QString str;
//    str = QString::number(yuv_index, 10);
//    tempFile->setFileName(str + ".yuv");
//    if(!tempFile->open(QIODevice::WriteOnly))
//    {
//        qDebug("打开失败");
//    }
////    char dataa[4147200];
//    char *p = new char[4147200];
//    for(int i = 0; i < 4050; i++)
//    {

//        char yuv_data[1024] = { 2 };
////        memcpy(p + i * 1024, yuv_data, 1024);
//        int len = tempFile->write(yuv_data, 1024);
////        qDebug("len:%d", len);
//    }
////    int len = tempFile->write(p, 1024*4050);
////    qDebug("len:%d", len);
//    tempFile->close();

//    qDebug()<<"第一段程序耗时："<<timedebuge.elapsed()/1000.0<<"s";//输出计时

    connect(&ppd,SIGNAL(send_index(int)),this, SLOT(show_index(int)));
    connect(&ppd,SIGNAL(send_idx(int)),this, SLOT(show_idx(int)));

}

void MainWindow::show_index(int index)
{
    ui->index_lab->setText(QString::number(index,10));
}

void MainWindow::show_idx(int idx)
{
    ui->label_3->setText(QString::number(idx,10));
}

void MainWindow::Ppacket_handler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data)
{

}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    int dex = ui->net_cBox->currentIndex();
    net_index = dex + 1;
    qDebug()<<dex;
    ppd.start();
}

void MainWindow::show_net()
{
        pcap_if_t *alldevs;
        pcap_if_t *d;
        char errbuf[PCAP_ERRBUF_SIZE];
    /* 获得设备列表 */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
//        fqDebug(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
//        exit(1);
        return;
    }

    /* 打印列表 */
    int i = 0;
    for(d=alldevs; d; d=d->next)
    {
//        qDebug("%d. %s", ++i, d->name);
        if (d->description)
        {
//            qDebug(" (%s)\n", d->description);
            QString name(d->description);
            ui->net_cBox->addItem(name);
        }
        else
            qDebug(" (No description available)\n");
    }
}

void MainWindow::on_pushButton_2_clicked()
{
    ppd.quitt();
}
