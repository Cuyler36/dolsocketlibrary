#ifndef __DOLPHIN_OS_IP_SOCKET_H__
#define __DOLPHIN_OS_IP_SOCKET_H__

#include <dolphin/ip/IP.h>
#include <dolphin/ip/IPDns.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SO_MTU_MAX 1500

#define SO_INADDR_ANY ((u32)0x00000000)

#define SO_GET_CONFIG_MTU(config) ((config)->mtu > SO_MTU_MAX ? SO_MTU_MAX : (config)->mtu)

typedef struct SOInAddr {
    // total size: 0x4
    u32 addr; // offset 0x0, size 0x4
} SOInAddr;

typedef struct SOSockAddrIn {
    u8 len;
    u8 family;
    u16 port;
    SOInAddr addr;
} SOSockAddrIn;

typedef struct SOIpMreq {
    // total size: 0x8
    SOInAddr multiaddr; // offset 0x0, size 0x4
    SOInAddr interface; // offset 0x4, size 0x4
} SOIpMreq;

typedef struct SONode {
    // total size: 0x38
    u8 proto; // offset 0x0, size 0x1
    u8 flag; // offset 0x1, size 0x1
    s16 ref; // offset 0x2, size 0x2
    IPInfo* info; // offset 0x4, size 0x4
    OSMutex mutexRead; // offset 0x8, size 0x18
    OSMutex mutexWrite; // offset 0x20, size 0x18
} SONode;

typedef struct SOSockAddr {
    // total size: 0x8
    u8 len; // offset 0x0, size 0x1
    u8 family; // offset 0x1, size 0x1
    u8 data[6]; // offset 0x2, size 0x6
} SOSockAddr;

typedef struct SOHostEnt {
    // total size: 0x10
    char* name; // offset 0x0, size 0x4
    char** aliases; // offset 0x4, size 0x4
    s16 addrType; // offset 0x8, size 0x2
    s16 length; // offset 0xA, size 0x2
    u8** addrList; // offset 0xC, size 0x4
} SOHostEnt;

typedef struct SOResolver {
    // total size: 0x790
    DNSInfo info; // offset 0x0, size 0x560
    SOHostEnt ent; // offset 0x560, size 0x10
    char name[256]; // offset 0x570, size 0x100
    char* zero; // offset 0x670, size 0x4
    u8 addrList[140]; // offset 0x674, size 0x8C
    u8* ptrList[36]; // offset 0x700, size 0x90
} SOResolver;

typedef void* (*SOAllocFunc)(u32, s32);
typedef void (*SOFreeFunc)(u32, void*, s32);

typedef struct SOConfig {
    // total size: 0x60
    u16 vendor; // offset 0x0, size 0x2
    u16 version; // offset 0x2, size 0x2
    SOAllocFunc alloc; // offset 0x4, size 0x4
    SOFreeFunc free; // offset 0x8, size 0x4
    u32 flag; // offset 0xC, size 0x4
    SOInAddr addr; // offset 0x10, size 0x4
    SOInAddr netmask; // offset 0x14, size 0x4
    SOInAddr router; // offset 0x18, size 0x4
    SOInAddr dns1; // offset 0x1C, size 0x4
    SOInAddr dns2; // offset 0x20, size 0x4
    s32 timeWaitBuffer; // offset 0x24, size 0x4
    s32 reassemblyBuffer; // offset 0x28, size 0x4
    s32 mtu; // offset 0x2C, size 0x4
    s32 rwin; // offset 0x30, size 0x4
    OSTime r2; // offset 0x38, size 0x8
    const char* peerid; // offset 0x40, size 0x4
    const char* passwd; // offset 0x44, size 0x4
    const char* serviceName; // offset 0x48, size 0x4
    const char* hostName; // offset 0x4C, size 0x4
    s32 rdhcp; // offset 0x50, size 0x4
    s32 udpSendBuff; // offset 0x54, size 0x4
    s32 udpRecvBuff; // offset 0x58, size 0x4
} SOConfig;

typedef struct SOLinger {
    // total size: 0x8
    int onoff; // offset 0x0, size 0x4
    int linger; // offset 0x4, size 0x4
} SOLinger;

typedef struct SOPollFD {
    // total size: 0x8
    int fd; // offset 0x0, size 0x4
    s16 events; // offset 0x4, size 0x2
    s16 revents; // offset 0x6, size 0x2
} SOPollFD;

s32 SOGetHostID();

typedef struct SOAddrInfo {
    // total size: 0x20
    int flags; // offset 0x0, size 0x4
    int family; // offset 0x4, size 0x4
    int sockType; // offset 0x8, size 0x4
    int protocol; // offset 0xC, size 0x4
    unsigned int addrLen; // offset 0x10, size 0x4
    char* canonName; // offset 0x14, size 0x4
    void* addr; // offset 0x18, size 0x4
    struct SOAddrInfo* next; // offset 0x1C, size 0x4
} SOAddrInfo;

void* SOAlloc(u32 name, s32 size);
void SOFree(u32 name, void* ptr, s32 size);
int SOInetPtoN(int af, const char* src, void* dst);
char* SOInetNtoP(int af, void* src, char* dst, u32 len);
int SOGetAddrInfoAsync(const char* nodeName, const char* servName, const SOAddrInfo* hints, DNSCommand* cmd, u8* addrList, DNSCallback callback, int* result);
int SOGetAddrInfo(const char* nodeName, const char* servName, const SOAddrInfo* hints, SOAddrInfo** res);
void SOFreeAddrInfo(SOAddrInfo* head);
void __IPWakeupPollingThreads(void);
int SOGetNameInfo(void* sa, char* node, unsigned int nodeLen, char* service, unsigned int serviceLen, int flags);
int SOSetResolver(const SOInAddr* dns1, const SOInAddr* dns2);
int SOGetResolver(SOInAddr* dns1, SOInAddr* dns2);
u32 SONtoHl(u32 netlong);
u16 SONtoHs(u16 netshort);
u32 SOHtoNl(u32 hostlong);
u16 SOHtoNs(u16 hostshort);
int SOInetAtoN(const char* cp, SOInAddr* inp);
char* SOInetNtoA(SOInAddr in);
void SOInit(void);
int SOStartup(const SOConfig* config);
int SOCleanup(void);
int SOSocket(int af, int type, int protocol);
int SOClose(int s);
int SOListen(int s, int backlog);
int SOAccept(int s, void* sockAddr);
int SOBind(int s, void* sockAddr);
int SOConnect(int s, void* sockAddr);
int SOGetPeerName(int s, void* sockAddr);
int SOGetSockName(int s, void* sockAddr);
int SOShutdown(int s, int how);
int SORead(int s, void* buf, int len);
int SORecv(int s, void* buf, int len, int flags);
int SORecvFrom(int s, void* buf, int len, int flags, void* sockFrom);
int SOWrite(int s, void* buf, int len);
int SOSend(int s, void* buf, int len, int flags);
int SOSendTo(int s, void* buf, int len, int flags, void* sockTo);
int SOSockAtMark(int s);
int SOGetSockOpt(int s, int level, int optname, void* optval, int* optlen);
int SOSetSockOpt(int s, int level, int optname, void* optval, int optlen);
int SOFcntl(int s, int cmd, ...);
SOHostEnt* SOGetHostByName(const char* name);
SOHostEnt* SOGetHostByAddr(void* addr, int len, int type);
int SOPoll(SOPollFD* fds, u32 nfds, OSTime timeout);

#ifdef __cplusplus
}
#endif

#endif
