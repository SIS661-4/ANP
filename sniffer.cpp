#include "sniffer.h"

sniffer::sniffer()
{

}

void sniffer::analis(QString str)
{
    waitWindow();
    file = new QFile(str);
    if(!file->open(QIODevice::ReadOnly))
        errorour();
    else
    {
        Name.nameOfFile = str;
        file->read((char *)&Name.magic, 4);
        file->read((char *)&Name.versionMajor, 2);
        file->read((char *)&Name.versionMinor, 2);
        file->read((char *)&Name.thisZone, 4);
        file->read((char *)&Name.sigfigs, 4);
        file->read((char *)&Name.snaplen, 4);
        file->read((char *)&Name.linkType, 4);
        while(file->pos() < file->size())
        {
            packets p;
            Packets.push_back(p);
            file->read((char *)&Packets[Packets.size() - 1].t1, 4);
            file->read((char *)&Packets[Packets.size() - 1].t2, 4);
            file->read((char *)&Packets[Packets.size() - 1].captureLen, 4);
            file->read((char *)&Packets[Packets.size() - 1].len, 4);
            for(int i = 0; i < Packets[Packets.size() - 1].captureLen; i++)
            {
                qint8 q;
                file->read((char *)&q, 1);
                Packets[Packets.size() - 1].file.push_back(q);
            }
        }
        Name.nomberOfPackets = Packets.size();
        outFirst(Name);
        outSecond(Packets);
    }
}
