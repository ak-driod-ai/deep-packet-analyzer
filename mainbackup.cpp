#include <iostream>
#include <fstream>
#include <cstdint>
#include <vector>
#include <cstdio>

using namespace std;

struct PcapGlobalHeader
{
    uint32_t magicNumber;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t thisZone;
    uint32_t sigFigs;
    uint32_t snapLen;
    uint32_t network;
};
struct PcapPacketHeader
{
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
struct IPv4Header
{
    uint8_t version;
    uint8_t headerLength;
    uint8_t ttl;
    uint8_t protocol;

    string sourceIP;
    string destinationIP;
};
struct TCPHeader
{
    uint16_t sourcePort;
    uint16_t destinationPort;

    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;

    uint8_t headerLength;

    bool syn;
    bool ack;
    bool fin;
};

int main()
{
    ifstream file("captures/sample.pcap", ios::binary);

    if (!file)
    {
        cout << "Could not open file!" << endl;
        return 1;
    }

    PcapGlobalHeader header;

    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    cout << "========== PCAP HEADER ==========\n";
    cout << "Magic Number : 0x" << hex << header.magicNumber << endl;
    cout << dec;
    cout << "Version      : "
         << header.versionMajor
         << "."
         << header.versionMinor << endl;

    cout << "Snap Length  : "
         << header.snapLen << endl;

    cout << "Link Type    : "
         << header.network << endl;

    PcapPacketHeader packetHeader;

file.read(reinterpret_cast<char*>(&packetHeader),
          sizeof(packetHeader));

cout << "\n====== FIRST PACKET ======\n";

cout << "Timestamp (sec): "
     << packetHeader.ts_sec << endl;

cout << "Timestamp (usec): "
     << packetHeader.ts_usec << endl;

cout << "Captured Length: "
     << packetHeader.incl_len << endl;
     if(packetHeader.incl_len<100){
        cout<<"Packet Size :Small"<<endl;
     }
     else if(packetHeader.incl_len<=1000){
        cout<<"Packet Size: Medium"<<endl;
     }
     else{
        cout<<"Packet Size : Large"<<endl;
     }

cout << "Original Length: "
     << packetHeader.orig_len << endl;
     vector<uint8_t> packetData(packetHeader.incl_len);

file.read(
    reinterpret_cast<char*>(packetData.data()),
    packetHeader.incl_len
);

cout << "\nFirst 20 Bytes of Packet\n";

for(int i = 0; i < 20 && i < packetData.size(); i++)
{
    printf("%02X ", packetData[i]);
}

cout << endl;
cout << "\n===== Ethernet Header =====\n";

cout << "Destination MAC : ";

for(int i = 0; i < 6; i++)
{
    printf("%02X", packetData[i]);

    if(i != 5)
        printf(":");
}

cout << endl;

cout << "Source MAC      : ";

for(int i = 6; i < 12; i++)
{
    printf("%02X", packetData[i]);

    if(i != 11)
        printf(":");
}

cout << endl;

uint16_t etherType =
    (packetData[12] << 8) | packetData[13];

printf("EtherType       : 0x%04X\n", etherType);

IPv4Header ip;
uint8_t firstByte = packetData[14];

ip.version = firstByte >> 4;
ip.headerLength = (firstByte & 0x0F) * 4;
ip.ttl = packetData[22];

ip.protocol = packetData[23];
string protocolName;

switch(ip.protocol)
{
case 1:
    protocolName = "ICMP";
    break;

case 6:
    protocolName = "TCP";
    break;

case 17:
    protocolName = "UDP";
    break;

default:
    protocolName = "Unknown";
}
ip.sourceIP =
    to_string(packetData[26]) + "." +
    to_string(packetData[27]) + "." +
    to_string(packetData[28]) + "." +
    to_string(packetData[29]);

ip.destinationIP =
    to_string(packetData[30]) + "." +
    to_string(packetData[31]) + "." +
    to_string(packetData[32]) + "." +
    to_string(packetData[33]);
    cout << "\n===== IPv4 Header =====\n";

cout << "Version          : "
     << (int)ip.version << endl;

cout << "Header Length    : "
     << (int)ip.headerLength
     << " bytes" << endl;

cout << "TTL              : "
     << (int)ip.ttl << endl;

cout << "Protocol         : "
     << protocolName << endl;

cout << "Source IP        : "
     << ip.sourceIP << endl;

cout << "Destination IP   : "
     << ip.destinationIP << endl;

     TCPHeader tcp;
     tcp.sourcePort =
    (packetData[34] << 8)
    | packetData[35];
    tcp.destinationPort =
    (packetData[36] << 8)
    | packetData[37];
    cout << "\n===== TCP Header =====\n";

cout << "Source Port      : "
     << tcp.sourcePort
     << endl;

cout << "Destination Port : "
     << tcp.destinationPort
     << endl;

file.close();



    return 0;
}