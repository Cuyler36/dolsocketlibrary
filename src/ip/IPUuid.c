#include <dolphin/ip.h>
#include <dolphin/ip/IPUuid.h>
#include <dolphin/private/ip.h>
#include <dolphin/md5.h>
#include <ctype.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

extern unsigned char __ctype_map[];

#define __isdigit(c) (__ctype_map[(u8)(c)] & 0x10)

// Range: 0x0 -> 0x3C
static u32 GetCounterBias(void) {
    // Local variables
    OSSram* sram; // r31
    u32 counterBias; // r30

    sram = __OSLockSram();
    counterBias = sram->counterBias;
    __OSUnlockSram(FALSE);
    return counterBias;
}

// Range: 0x3C -> 0xBC
void IPPrintUuid(const IPUuid* u /* r31 */) {
    // Local variables
    int i; // r30

    OSReport("%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u->timeLow, u->timeMid, u->timeHiAndVersion, u->clockSeqHiAndReserved, u->clockSeqLow);
    for (i = 0; i < 6; i++) {
        OSReport("%2.2x", u->node[i]);
    }
    OSReport("\n");
}

// Range: 0xBC -> 0x170
char* IPGetUuidString(const IPUuid* u /* r30 */, char* str /* r27 */) {
    // Local variables
    int i; // r28
    char* ptr; // r31

    ptr = str;
    ptr += sprintf(ptr, "%8.8x-%4.4x-%4.4x-%2.2x%2.2x-", u->timeLow, u->timeMid, u->timeHiAndVersion, u->clockSeqHiAndReserved, u->clockSeqLow);
    for (i = 0; i < 6; i++) {
        ptr += sprintf(ptr, "%2.2x", u->node[i]);
    }
    ASSERTLINE(113, ptr - str == IP_UUID_STR_LEN - 1);
    return str;
}

// Range: 0x170 -> 0x2B4
int IPScanUuid(const char* str /* r25 */, IPUuid* u /* r1+0xC */) {
    // Local variables
    int x; // r31
    int b; // r29
    u8* p; // r26
    int i; // r30
    int j; // r27

    // References
    // -> unsigned char __ctype_map[];

    p = (u8*)u;
    for (i = 0, j = 0; i < IP_UUID_STR_LEN - 1; i++) {
        switch (i) {
            case 8:
            case 13:
            case 18:
            case 23:
                if (str[i] != '-') {
                    return -1;
                }
                break;
            default:
                x = str[i];
                if (!isxdigit(x)) {
                    return -1;
                }
                if (__isdigit(x)) {
                    x -= '0';
                } else {
                    x = tolower(x);
                    x -= 'a';
                    x += 10;
                }
                if (j & 1) {
                    b = (b << 4) | x;
                    *p++ = (u8)b;
                } else {
                    b = x;
                }
                j++;
                ASSERTLINE(169, b < 256);
                break;
        }
    }
    ASSERTLINE(171, j == 32);
    return 0;
}

// Range: 0x2B4 -> 0x498
int IPCreateUuid(IPUuid* uuid /* r31 */) {
    // Local variables
    int enabled; // r26
    u64 timestamp; // r29
    u16 clockseq; // r27
    u32 bias; // r28
    u8 node[6]; // r1+0x18
    s64 random; // r1+0x10
    static u64 lasttime;

    // References
    // -> static unsigned long long lasttime$47;

    enabled = OSDisableInterrupts();
    do {
        timestamp = (OSGetTime() * 80) / (OS_TIMER_CLOCK / 125000) + 0x01C0B0D0B4D64000;
        timestamp &= 0x0FFFFFFFFFFFFFFF;
    } while (lasttime == timestamp);
    lasttime = timestamp;

    bias = GetCounterBias();
    IPGetMacAddr(NULL, node);
    if (node[1] == 0) {
        random = OSGetTime();
        random ^= __OSGetSystemTime();
        random ^= ~bias;
        random ^= (s64)bias << 32;
        memmove(node, &random, 6);
        node[0] |= 0x80;
    }

    clockseq = bias & 0x3FFF;
    uuid->timeLow = (u32)timestamp;
    uuid->timeMid = (u16)(timestamp >> 32);
    uuid->timeHiAndVersion = (u16)(timestamp >> 48);
    uuid->timeHiAndVersion |= 0x1000;
    uuid->clockSeqLow = (u8)clockseq;
    uuid->clockSeqHiAndReserved = (u8)(clockseq >> 8);
    uuid->clockSeqHiAndReserved |= 0x80;
    memmove(uuid->node, node, 6);

    OSRestoreInterrupts(enabled);
    return TRUE;
}

// Range: 0x498 -> 0x520
int IPCreateUuid4(IPUuid* uuid /* r31 */) {
    // Local variables
    MD5Context context; // r1+0xC

    IPCreateUuid(uuid);
    MD5Init(&context);
    MD5Update(&context, (u8*)uuid, sizeof(IPUuid));
    MD5Final((u8*)uuid, &context);
    uuid->timeHiAndVersion &= ~0xF000;
    uuid->timeHiAndVersion |= 0x4000;
    uuid->clockSeqHiAndReserved &= ~0xC0;
    uuid->clockSeqHiAndReserved |= 0x80;
    return TRUE;
}

// Range: 0x520 -> 0x67C
int IPCompareUuid(const IPUuid* u1 /* r3 */, const IPUuid* u2 /* r4 */) {
    // Local variables
    int i; // r31

    if (u1->timeLow != u2->timeLow) {
        return (u1->timeLow < u2->timeLow) ? -1 : 1;
    }
    if (u1->timeMid != u2->timeMid) {
        return (u1->timeMid < u2->timeMid) ? -1 : 1;
    }
    if (u1->timeHiAndVersion != u2->timeHiAndVersion) {
        return (u1->timeHiAndVersion < u2->timeHiAndVersion) ? -1 : 1;
    }
    if (u1->clockSeqHiAndReserved != u2->clockSeqHiAndReserved) {
        return (u1->clockSeqHiAndReserved < u2->clockSeqHiAndReserved) ? -1 : 1;
    }
    if (u1->clockSeqLow != u2->clockSeqLow) {
        return (u1->clockSeqLow < u2->clockSeqLow) ? -1 : 1;
    }
    for (i = 0; i < 6; i++) {
        if (u1->node[i] < u2->node[i]) {
            return -1;
        }
        if (u1->node[i] > u2->node[i]) {
            return 1;
        }
    }
    return 0;
}
