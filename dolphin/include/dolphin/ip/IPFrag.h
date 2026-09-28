#ifndef __DOLPHIN_OS_IP_FRAG_H__
#define __DOLPHIN_OS_IP_FRAG_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_FRAG_BITS 0x1FFF
#define IP_HAS_FRAG 0x2000
#define IP_DONT_FRAG 0x4000
#define IP_MF IP_HAS_FRAG
#define IP_DF IP_DONT_FRAG

#define IP_FRAG(ip) (((ip)->frag & IP_FRAG_BITS) << 3)

typedef struct IPReassembleControl {
    // total size: 0x40
    u32 flag; // offset 0x0, size 0x4
    u8* buffer; // offset 0x4, size 0x4
    s32 len; // offset 0x8, size 0x4
    s32 mtu; // offset 0xC, size 0x4
    s32 size; // offset 0x10, size 0x4
    OSAlarm alarm; // offset 0x18, size 0x28
} IPReassembleControl;

typedef struct IPReassembled {
    // total size: 0x60
    IPInterface* interface; // offset 0x0, size 0x4
    u32 flag; // offset 0x4, size 0x4
    IPHeader first; // offset 0x8, size 0x14
    u8 option[40]; // offset 0x1C, size 0x28
    u8 data[8]; // offset 0x44, size 0x8
    IPHeader header; // offset 0x4C, size 0x14
} IPReassembled;

typedef struct IPHole {
    // total size: 0x8
    u16 first; // offset 0x0, size 0x2
    u16 last; // offset 0x2, size 0x2
    u16 next; // offset 0x4, size 0x2
    u16 _unused; // offset 0x6, size 0x2
} IPHole;

s32 IPSetReassemblyBuffer(void* buffer, s32 len, s32 mtu);
IPHeader* IPReassemble(IPInterface* interface, IPHeader* frag, u32 flag);
int IPFragment(IFDatagram* datagram, u8* ptr, BOOL* discard);

#ifdef __cplusplus
}
#endif

#endif
