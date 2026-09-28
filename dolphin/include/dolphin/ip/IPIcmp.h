#ifndef __DOLPHIN_OS_IP_ICMP_H__
#define __DOLPHIN_OS_IP_ICMP_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ICMPHeader {
    // total size: 0x4
    u8 type; // offset 0x0, size 0x1
    u8 code; // offset 0x1, size 0x1
    u16 sum; // offset 0x2, size 0x2
} ICMPHeader;

typedef struct ICMPUnreachable {
    // total size: 0x8
    u8 type; // offset 0x0, size 0x1
    u8 code; // offset 0x1, size 0x1
    u16 sum; // offset 0x2, size 0x2
    u16 unused; // offset 0x4, size 0x2
    u16 mtu; // offset 0x6, size 0x2
} ICMPUnreachable;

typedef struct ICMPRedirect {
    // total size: 0x8
    u8 type; // offset 0x0, size 0x1
    u8 code; // offset 0x1, size 0x1
    u16 sum; // offset 0x2, size 0x2
    u8 gateway[4]; // offset 0x4, size 0x4
} ICMPRedirect;

void ICMPIn(IPInterface * interface /* r27 */, IPHeader * ip /* r31 */, u32 flag /* r26 */);
typedef struct ICMPTimeExceeded {
    // total size: 0x8
    u8 type; // offset 0x0, size 0x1
    u8 code; // offset 0x1, size 0x1
    u16 sum; // offset 0x2, size 0x2
    u32 unused; // offset 0x4, size 0x4
} ICMPTimeExceeded;

s32 ICMPSendError(ICMPHeader* icmp, IPInterface* interface, IPHeader* ip, u32 flag);

#ifdef __cplusplus
}
#endif

#endif
