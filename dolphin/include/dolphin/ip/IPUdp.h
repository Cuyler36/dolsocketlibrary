#ifndef __DOLPHIN_OS_IP_UDP_H__
#define __DOLPHIN_OS_IP_UDP_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UDP_HLEN 8

typedef struct UDPHeader {
    // total size: 0x8
    u16 src; // offset 0x0, size 0x2
    u16 dst; // offset 0x2, size 0x2
    u16 len; // offset 0x4, size 0x2
    u16 sum; // offset 0x6, size 0x2
} UDPHeader;

typedef struct UDPInfo UDPInfo;
typedef void (*UDPCallback)(UDPInfo*, s32);

struct UDPInfo {
    // total size: 0xF0
    IPInfo pair; // offset 0x0, size 0x20
    OSThreadQueue queueThread; // offset 0x20, size 0x8
    u32 flag; // offset 0x28, size 0x4
    UDPCallback sendCallback; // offset 0x2C, size 0x4
    s32* sendResult; // offset 0x30, size 0x4
    IFDatagram datagram; // offset 0x34, size 0x3C
    IFVec vec[1]; // offset 0x70, size 0x8
    u8 header[68]; // offset 0x78, size 0x44
    UDPCallback recvCallback; // offset 0xBC, size 0x4
    s32* recvResult; // offset 0xC0, size 0x4
    void* data; // offset 0xC4, size 0x4
    s32 len; // offset 0xC8, size 0x4
    IPSocket* local; // offset 0xCC, size 0x4
    IPSocket* remote; // offset 0xD0, size 0x4
    u8* recvRing; // offset 0xD4, size 0x4
    s32 recvBuff; // offset 0xD8, size 0x4
    u8* recvPtr; // offset 0xDC, size 0x4
    s32 recvUsed; // offset 0xE0, size 0x4
    u8* sendData; // offset 0xE4, size 0x4
    s32 sendBuff; // offset 0xE8, size 0x4
    s32 sendUsed; // offset 0xEC, size 0x4
};

u16 UDPCheckSum(IFVec* vec, s32 nVec);
void UDPNotify(IPHeader* ip, const u8* gateway, s32 err);
void UDPIn(IPInterface* interface, IPHeader* ip, u32 flag);
BOOL UDPOnReset(BOOL final);
s32 UDPGetRemoteSocket(UDPInfo* info, IPSocket* socket);
s32 UDPGetLocalSocket(UDPInfo* info, IPSocket* socket);
s32 UDPSetOption(UDPInfo* info, u8 ttl, u8 tos);
s32 UDPConnect(UDPInfo* info, const IPSocket* socket);
s32 UDPGetRecvBuff(UDPInfo* info, void* recvbuf, s32* recvbufLen);
s32 UDPSetRecvBuff(UDPInfo* info, void* recvbuf, s32 recvbufLen);
s32 UDPGetSendBuff(UDPInfo* info, void* sendbuf, s32* sendbufLen);
s32 UDPSetSendBuff(UDPInfo* info, void* sendbuf, s32 sendbufLen);
s32 UDPOpen(UDPInfo* info, void* recvbuf, s32 recvbufLen);
s32 UDPBind(UDPInfo* info, const IPSocket* socket);
s32 UDPSendAsync(UDPInfo* info, void* data, s32 len, const IPSocket* remote, UDPCallback callback, s32* result);
s32 UDPSend(UDPInfo* info, void* data, s32 len, const IPSocket* remote);
s32 UDPReceiveExAsync(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote, u32 flag, UDPCallback callback, s32* result);
s32 UDPReceiveAsync(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote, UDPCallback callback, s32* result);
s32 UDPReceiveNonblock(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote);
s32 UDPReceiveEx(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote, u32 flag);
s32 UDPReceive(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote);
s32 UDPPeek(UDPInfo* info, void* data, s32 len, IPSocket* local, IPSocket* remote);
s32 UDPCancel(UDPInfo* info);
s32 UDPClose(UDPInfo* info);
s32 UDPGetSockOpt(UDPInfo* info, int level, int optname, void* optval, int* optlen);
s32 UDPSetSockOpt(UDPInfo* info, int level, int optname, void* optval, int optlen);
s16 __UDPPoll(UDPInfo* info);

extern IFQueue UDPInfoQueue;

#ifdef __cplusplus
}
#endif

#endif
