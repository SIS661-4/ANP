#ifndef PACKETS_H
#define PACKETS_H

#include <QObject>
#include <QString>
#include <QVector>

struct name
{
    qint32 magic;
    qint16 versionMajor;
    qint16 versionMinor;
    qint32 thisZone;
    qint32 sigfigs;
    qint32 snaplen;
    qint32 linkType;
    qint32 nomberOfPackets;
    QString nameOfFile;
};

struct packets
{
    qint32 t1;
    qint32 t2;
    qint32 captureLen;
    qint32 len;
    QVector <qint8> file;
};

#endif // PACKETS_H
