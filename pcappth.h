#ifndef PCAPPTH_H
#define PCAPPTH_H

//#include <QObject>
#include <QThread>
//#include ""


#include "utils.h"

//extern unsigned char
//extern unsigned char yuv_index1;
//extern unsigned char yuv_data1[4147200];

class pcapPth : public QThread
{
    Q_OBJECT
public:
    explicit pcapPth(QObject *parent = 0);
    void run();
    void quitt();

signals:
    void send_index(int);
    void send_idx(int);

public slots:
private:
    bool qq;

};

#endif // PCAPPTH_H
