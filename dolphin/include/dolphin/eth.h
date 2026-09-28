#ifndef _DOLPHIN_ETH_H_
#define _DOLPHIN_ETH_H_

#include <dolphin/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* (*ETHCallback0)(u16 type);
typedef void (*ETHCallback1)(u8* addr, s32 length);
typedef void (*ETHCallback2)(u8 ltps);

s32 ETHInit(s32 mode);
void ETHGetMACAddr(u8* macaddr);
void ETHSetRecvCallback(ETHCallback0 callback0, ETHCallback1 callback1);
BOOL ETHGetLinkStateAsync(s32* status);
void ETHSetProtoType(u16* array, s32 num);
void ETHSendAsync(void* addr, s32 length, ETHCallback2 callback2);
void ETHClearMulticastAddresses(void);

#ifdef __cplusplus
}
#endif

#endif // _DOLPHIN_ETH_H_
