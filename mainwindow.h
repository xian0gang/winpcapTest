#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
//#include "pthread_compat.h"
#include <pcappth.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void Ppacket_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void show_net();

private slots:
    void on_pushButton_clicked();
    void show_index(int);
    void show_idx(int);

    void on_pushButton_2_clicked();

private:
    Ui::MainWindow *ui;
//    pcap_if_t *alldevs;
//    pcap_if_t *d;
    pcapPth ppd;
};

#endif // MAINWINDOW_H
