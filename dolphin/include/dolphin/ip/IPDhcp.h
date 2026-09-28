#ifndef __DOLPHIN_OS_IP_DHCP_H__
#define __DOLPHIN_OS_IP_DHCP_H__

#include <dolphin/ip/IP.h>
#include <dolphin/ip/IPUdp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DHCP_OPT_DNS 6

typedef struct DHCPInfo {
    // total size: 0x22C
    u8 ipaddr[4]; // offset 0x0, size 0x4
    u8 netmask[4]; // offset 0x4, size 0x4
    u8 router[4]; // offset 0x8, size 0x4
    u8 dns1[4]; // offset 0xC, size 0x4
    u8 dns2[4]; // offset 0x10, size 0x4
    char host[256]; // offset 0x14, size 0x100
    char domain[256]; // offset 0x114, size 0x100
    u16 mtu; // offset 0x214, size 0x2
    u8 broadcast[4]; // offset 0x216, size 0x4
    u32 lease; // offset 0x21C, size 0x4
    u8 server[4]; // offset 0x220, size 0x4
    u32 renewal; // offset 0x224, size 0x4
    u32 rebinding; // offset 0x228, size 0x4
} DHCPInfo;

typedef struct DHCPHeader {
    // total size: 0xEC
    u8 op; // offset 0x0, size 0x1
    u8 htype; // offset 0x1, size 0x1
    u8 hlen; // offset 0x2, size 0x1
    u8 hops; // offset 0x3, size 0x1
    u32 xid; // offset 0x4, size 0x4
    u16 secs; // offset 0x8, size 0x2
    u16 flags; // offset 0xA, size 0x2
    u8 ciaddr[4]; // offset 0xC, size 0x4
    u8 yiaddr[4]; // offset 0x10, size 0x4
    u8 siaddr[4]; // offset 0x14, size 0x4
    u8 giaddr[4]; // offset 0x18, size 0x4
    u8 chaddr[16]; // offset 0x1C, size 0x10
    u8 sname[64]; // offset 0x2C, size 0x40
    u8 file[128]; // offset 0x6C, size 0x80
} DHCPHeader;

typedef struct DHCPControl {
    // total size: 0x938
    UDPInfo udp; // offset 0x0, size 0xF0
    int state; // offset 0xF0, size 0x4
    u32 xid; // offset 0xF4, size 0x4
    u32 flag; // offset 0xF8, size 0x4
    IPSocket socket; // offset 0xFC, size 0x8
    u8 heap[536]; // offset 0x104, size 0x218
    s32 len; // offset 0x31C, size 0x4
    int rxmitMax; // offset 0x320, size 0x4
    int rxmitCount; // offset 0x324, size 0x4
    OSAlarm rxmitAlarm; // offset 0x328, size 0x28
    OSAlarm t1; // offset 0x350, size 0x28
    OSAlarm t2; // offset 0x378, size 0x28
    OSAlarm expire; // offset 0x3A0, size 0x28
    s64 t2Time; // offset 0x3C8, size 0x8
    s64 expireTime; // offset 0x3D0, size 0x8
    DHCPInfo info; // offset 0x3D8, size 0x22C
    DHCPInfo tempInfo; // offset 0x604, size 0x22C
    void (*callback)(int); // offset 0x830, size 0x4
    char hostName[256]; // offset 0x834, size 0x100
} DHCPControl;

void DHCPDump(DHCPHeader* dhcp, s32 optlen);
int DHCPProcessOptions(DHCPHeader* dhcp, int mlen, DHCPInfo* info);
int DHCPStartupEx(void (*callback)(int), int rxmitMax, const char* hostName);
int DHCPGetOpt(int opt, void* buf, int len);
BOOL DHCPGetStatus(DHCPInfo * info /* r28 */);
BOOL DHCPReboot(void);
BOOL DHCPAuto(BOOL enable);
int DHCPStartup(void (*callback)(int));
int DHCPCleanup(void);

#ifdef __cplusplus
}
#endif

#endif

