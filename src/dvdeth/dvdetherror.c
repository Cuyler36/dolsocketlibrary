#include <dolphin/dvdeth.h>

#define DIDNT_MATCH 29

static u32 ErrorTable[18] = {
    0x00000000, 0x00023A00, 0x00062800, 0x00030200, 0x00031100, 0x00052000,
    0x00052001, 0x00052100, 0x00052400, 0x00052401, 0x00052402, 0x000B5A01,
    0x00056300, 0x00020401, 0x00020400, 0x00040800, 0x00100007, 0x00000000,
}; // size: 0x48, address: 0x0

// Range: 0x0 -> 0xA0
static u8 ErrorCode2Num(u32 errorCode /* r29 */) {
    // Local variables
    u32 i; // r31

    // References
    // -> static unsigned long ErrorTable[18];
    for (i = 0; i < sizeof(ErrorTable) / sizeof(ErrorTable[0]); i++) {
        if (errorCode == ErrorTable[i]) {
            ASSERTLINE(71, i < DIDNT_MATCH);
            return (u8)i;
        }
    }

    if (errorCode >= 0x100000 && errorCode <= 0x100008) {
        return 17;
    }

    return DIDNT_MATCH;
}

// Range: 0xA0 -> 0x11C
static u8 Convert(u32 error /* r30 */) {
    // Local variables
    u32 statusCode; // r31
    u32 errorCode; // r29
    u8 errorNum; // r28

    if (error == 0x01234567) {
        return 255;
    }

    if (error == 0x01234568) {
        return 254;
    }

    statusCode = (error & 0xFF000000) >> 24;
    errorCode = error & 0x00FFFFFF;
    errorNum = ErrorCode2Num(errorCode);
    if (statusCode >= 6) {
        statusCode = 6;
    }

    return (u8)(errorNum + statusCode * 30);
}

// Range: 0x11C -> 0x164
void __DVDStoreErrorCode(u32 error /* r1+0x8 */) {
    // Local variables
    OSSramEx* sram; // r31
    u8 num; // r30

    num = Convert(error);
    sram = __OSLockSramEx();
    sram->dvdErrorCode = num;
    __OSUnlockSramEx(TRUE);
}
