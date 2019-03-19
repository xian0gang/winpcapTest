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
        mainwindow.cpp \
    pcappth.cpp \
    utils.cpp

HEADERS  += mainwindow.h \
    pcappth.h \
    utils.h

FORMS    += mainwindow.ui

INCLUDEPATH += $$PWD/WpdPack/Include
LIBS += D:/git/gitclone/winpcapTest/WpdPack/Lib/wpcap.lib
LIBS += -lWs2_32
