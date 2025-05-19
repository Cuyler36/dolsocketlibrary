#ifndef __DOLPHIN_OS_IP_DHCP_H__
#define __DOLPHIN_OS_IP_DHCP_H__

#include <dolphin/ip/IP.h>

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
    u8 lease; // offset 0x21C, size 0x4
    u8 server[4]; // offset 0x220, size 0x4
    u8 renewal; // offset 0x224, size 0x4
    u8 rebinding; // offset 0x228, size 0x4
} DHCPInfo;

int DHCPGetOpt(int opt, void* buf, int len);
BOOL DHCPGetStatus(DHCPInfo * info /* r28 */);

#ifdef __cplusplus
}
#endif

#endif

