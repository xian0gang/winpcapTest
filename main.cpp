#include "mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QTextStream>

#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
void customMessageHandler(QtMsgType type, const QMessageLogContext &, const QString & str)
{
    QString txt=str;
#else
void customMessageHandler(QtMsgType type, const char *msg)
{
    QString txt(msg);
#endif
    QFile outFile("debug.log");
    outFile.open(QIODevice::WriteOnly | QIODevice::Append);
    QTextStream ts(&outFile);
    ts << txt << endl;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
//    qInstallMessageHandler(customMessageHandler);
#else
    qInstallMsgHandler(customMessageHandler);
#endif


    MainWindow w;
    w.show();

    return a.exec();
}
