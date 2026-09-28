#ifndef __DOLPHIN_OS_IP_IGMP_H__
#define __DOLPHIN_OS_IP_IGMP_H__

#include <dolphin/ip/IP.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IGMP {
    // total size: 0x8
    u8 vertype; // offset 0x0, size 0x1
    u8 unused; // offset 0x1, size 0x1
    u16 sum; // offset 0x2, size 0x2
    u8 addr[4]; // offset 0x4, size 0x4
} IGMP;

typedef struct IGMPInfo {
    // total size: 0x38
    u8 addr[4]; // offset 0x0, size 0x4
    u8 interface[4]; // offset 0x4, size 0x4
    OSAlarm alarm; // offset 0x8, size 0x28
    s16 ref; // offset 0x30, size 0x2
} IGMPInfo;

extern const u8 IPAllHosts[4];

s32 IPMulticastLookup(const u8* groupAddr, const u8* interface);
s32 IPMulticastJoin(const u8* groupAddr, const u8* interface);
s32 IPMulticastLeave(const u8* groupAddr, const u8* interface);

BOOL IPJoinLocalGroup(IPInterface* interface, const u8* groupAddr);
BOOL IPLeaveLocalGroup(void);
u16 IGMPCheckSum(IGMP* igmp);
IGMPInfo* IGMPLookupInfo(u8* groupAddr);
void IGMPInit(IPInterface* interface);
BOOL IGMPOnReset(BOOL final);
s32 IPClose(IPInfo* info);
void IGMPIn(IPInterface* interface, IPHeader* ip, u32 flag);

#ifdef __cplusplus
}
#endif

#endif
