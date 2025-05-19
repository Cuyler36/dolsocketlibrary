#ifndef __DOLPHIN_OS_IP_ETHER_H__
#define __DOLPHIN_OS_IP_ETHER_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL IFMute(BOOL mute);
BOOL IFInit(s32 type /* r30 */);

#ifdef __cplusplus
}
#endif

#endif

