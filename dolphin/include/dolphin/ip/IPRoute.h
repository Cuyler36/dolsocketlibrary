#ifndef __DOLPHIN_OS_IP_ROUTE_H__
#define __DOLPHIN_OS_IP_ROUTE_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IPRoute {
    // total size: 0x28
    IFQueue link; // offset 0x0, size 0x8
    u8 dst[4]; // offset 0x8, size 0x4
    u8 netmask[4]; // offset 0xC, size 0x4
    u8 gateway[4]; // offset 0x10, size 0x4
    u32 flag; // offset 0x14, size 0x4
    s64 time; // offset 0x18, size 0x8
    IPInterface* interface; // offset 0x20, size 0x4
} IPRoute;

void IPGetBroadcastAddr(IPInterface* interface, u8* broadcastAddr);
void IPGetNetmask(IPInterface* interface, u8* netmask);
void IPGetAddr(IPInterface* interface, u8* addr);
void IPGetGateway(IPInterface* interface, u8* gateway);
void IPGetAlias(IPInterface* interface, u8* alias);
void IPGetInterfaceStat(IPInterface* interface, IPInterfaceStat* stat);
void IPClearInterfaceStat(IPInterface* interface);
void IPSetNetmask(IPInterface* interface, const u8* netmask);
void IPSetAddr(IPInterface* interface, const u8* addr);
void IPSetGateway(IPInterface* interface, const u8* gateway);
void IPPrintRoutingTable(void);
BOOL IPAddRoute(const u8* dst, const u8* netmask, const u8* gateway);
BOOL IPRemoveRoute(const u8* dst, const u8* netmask, const u8* gateway);
s32 IPGetConfigError(IPInterface* interface);
s32 IPClearConfigError(IPInterface* interface);
IPInterface* IPGetRoute(const u8* addr, u8* dst);
BOOL IPIsBroadcastAddr(IPInterface* interface, const u8* addr);
BOOL IPIsLoopbackAddr(IPInterface* interface, const u8* addr);
BOOL IPIsLocalAddr(IPInterface* interface, const u8* addr);
void IPSetMtu(IPInterface * interface /* r31 */, s32 mtu /* r30 */);
void IPSetAlias(IPInterface* interface, const u8* alias);
BOOL IPRefreshRoute(void);
BOOL IPInitRoute(const u8* addr, const u8* netmask, const u8* gateway);
void IPGetMacAddr(IPInterface* interface, u8* macAddr);
int IPRedirect(const u8* dst, const u8* gateway, const u8* router);
void IPGetLinkState(IPInterface* interface, int* up);
void IPSetBroadcastAddr(IPInterface* interface, const u8* broadcastAddr);
void IPGetMtu(IPInterface* interface, s32* mtu);

#ifdef __cplusplus
}
#endif

#endif
