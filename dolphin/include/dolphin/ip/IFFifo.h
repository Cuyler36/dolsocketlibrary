#ifndef __DOLPHIN_OS_IP_IFFIFO_H__
#define __DOLPHIN_OS_IP_IFFIFO_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IFBlock {
    // total size: 0x8
    u8* ptr; // offset 0x0, size 0x4
    s32 len; // offset 0x4, size 0x4
} IFBlock;

typedef struct IFFifo {
    // total size: 0x10
    u8* buff; // offset 0x0, size 0x4
    s32 size; // offset 0x4, size 0x4
    u8* head; // offset 0x8, size 0x4
    s32 used; // offset 0xC, size 0x4
} IFFifo;

#ifdef __cplusplus
}
#endif

#endif
