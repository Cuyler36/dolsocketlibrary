#ifndef __DOLPHIN_OS_IP_UUID_H__
#define __DOLPHIN_OS_IP_UUID_H__

#include <dolphin/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IP_UUID_STR_LEN 37

typedef struct IPUuid {
    u32 timeLow;                // offset 0x0, size 0x4
    u16 timeMid;                // offset 0x4, size 0x2
    u16 timeHiAndVersion;       // offset 0x6, size 0x2
    u8 clockSeqHiAndReserved;   // offset 0x8, size 0x1
    u8 clockSeqLow;             // offset 0x9, size 0x1
    u8 node[6];                 // offset 0xA, size 0x6
} IPUuid;

void IPPrintUuid(const IPUuid* u);
char* IPGetUuidString(const IPUuid* u, char* str);
int IPScanUuid(const char* str, IPUuid* u);
int IPCreateUuid(IPUuid* uuid);
int IPCreateUuid4(IPUuid* uuid);
int IPCompareUuid(const IPUuid* u1, const IPUuid* u2);

#ifdef __cplusplus
}
#endif

#endif
