#ifndef __DOLPHIN_OS_IP_ETHER_H__
#define __DOLPHIN_OS_IP_ETHER_H__

#include <dolphin/ip/IP.h>
#include <dolphin/eth.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ETHHeader {
    // total size: 0xE
    u8 dst[6]; // offset 0x0, size 0x6
    u8 src[6]; // offset 0x6, size 0x6
    u16 type; // offset 0xC, size 0x2
} ETHHeader;

#ifndef ETH_ARP
#define ETH_ARP 0x0806
#endif
#ifndef ETH_PPPoE_DISCOVERY
#define ETH_PPPoE_DISCOVERY 0x8863
#endif
#ifndef ETH_PPPoE_SESSION
#define ETH_PPPoE_SESSION 0x8864
#endif
#ifndef IF_TYPE_NONE
#define IF_TYPE_NONE 5
#endif

BOOL IFMute(BOOL mute);
BOOL IFInit(s32 type /* r30 */);
void ETHIn(IPInterface* interface, ETHHeader* eh, s32 len);
void ETHOut(IPInterface* interface, IFDatagram* datagram);
void ETHAddMulticastAddress(const u8* macaddr);

#ifdef __cplusplus
}
#endif

#endif

