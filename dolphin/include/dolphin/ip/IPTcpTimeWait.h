#ifndef __DOLPHIN_OS_IP_TCPTIMEWAIT_H__
#define __DOLPHIN_OS_IP_TCPTIMEWAIT_H__

#include <dolphin/ip.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TCPTimeWaitInfo {
    // total size: 0x18
    u8 remoteAddr[4]; // offset 0x0, size 0x4
    u8 localAddr[4]; // offset 0x4, size 0x4
    u16 remotePort; // offset 0x8, size 0x2
    u16 localPort; // offset 0xA, size 0x2
    s32 sendMax; // offset 0xC, size 0x4
    s32 recvNext; // offset 0x10, size 0x4
    u32 expire; // offset 0x14, size 0x4
} TCPTimeWaitInfo;

typedef struct TCPTimeWaitControl {
    // total size: 0x14
    TCPTimeWaitInfo* array; // offset 0x0, size 0x4
    TCPTimeWaitInfo* end; // offset 0x4, size 0x4
    TCPTimeWaitInfo* head; // offset 0x8, size 0x4
    s32 used; // offset 0xC, size 0x4
    s32 max; // offset 0x10, size 0x4
} TCPTimeWaitControl;

s32 TCPSetTimeWaitBuffer(void* buffer, s32 len);
BOOL TCPLookupTimeWaitInfo(const u8* src, u16 srcPort, const u8* dst, u16 dstPort);
// TCPTestTimeWait / TCPStartTimeWait are declared in IPTcp.h (they need TCPInfo/TCPHeader)

#ifdef __cplusplus
}
#endif

#endif
