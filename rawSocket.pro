#-------------------------------------------------
#
# Project created by QtCreator 2019-03-14T21:56:35
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = rawSocket
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

INCLUDEPATH += E:/Qt/qtForAndroidExample/rawSocket/WpdPack/include
LIBS += E:/Qt/qtForAndroidExample/rawSocket/WpdPack/Lib/wpcap.lib
LIBS += -lWs2_32
