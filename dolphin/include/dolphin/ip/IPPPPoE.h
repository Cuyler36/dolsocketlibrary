#ifndef __DOLPHIN_OS_IP_PPPOE_H__
#define __DOLPHIN_OS_IP_PPPOE_H__

#include <dolphin/ip/IP.h>
#include <dolphin/ip/IPEther.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PPPoE codes */
#define PPPoE_SESSION 0x00
#define PPPoE_PADI    0x09
#define PPPoE_PADO    0x07
#define PPPoE_PADR    0x19
#define PPPoE_PADS    0x65
#define PPPoE_PADT    0xA7

/* PPPoE tag types */
#define PPPoE_TAG_END_OF_LIST        0x0000
#define PPPoE_TAG_SERVICE_NAME       0x0101
#define PPPoE_TAG_AC_NAME            0x0102
#define PPPoE_TAG_HOST_UNIQ          0x0103
#define PPPoE_TAG_AC_COOKIE          0x0104
#define PPPoE_TAG_VENDOR_SPECIFIC    0x0105
#define PPPoE_TAG_RELAY_SESSION_ID   0x0110
#define PPPoE_TAG_SERVICE_NAME_ERROR 0x0201
#define PPPoE_TAG_AC_SYSTEM_ERROR    0x0202
#define PPPoE_TAG_GENERIC_ERROR      0x0203

typedef struct PPPoEHeader {
    // total size: 0x6
    u8 vertype; // offset 0x0, size 0x1
    u8 code; // offset 0x1, size 0x1
    u16 session; // offset 0x2, size 0x2
    u16 len; // offset 0x4, size 0x2
} PPPoEHeader;

typedef struct PPPoETag {
    // total size: 0x4
    u16 type; // offset 0x0, size 0x2
    u16 len; // offset 0x2, size 0x2
} PPPoETag;

typedef struct PPPoEConf {
    // total size: 0x628
    u8 code; // offset 0x0, size 0x1
    u16 session; // offset 0x2, size 0x2
    u16 last; // offset 0x4, size 0x2
    u8 lastmac[6]; // offset 0x6, size 0x6
    OSAlarm alarm; // offset 0x10, size 0x28
    u8 mac[6]; // offset 0x38, size 0x6
    u8 pppoe[1500]; // offset 0x3E, size 0x5DC
    u16 len; // offset 0x61A, size 0x2
    u16 rxmit; // offset 0x61C, size 0x2
    IPInterface* interface; // offset 0x620, size 0x4
    void (*out)(IPInterface*, IFDatagram*); // offset 0x624, size 0x4
} PPPoEConf;

void PPPoEDumpPacket(PPPoEHeader* pppoe);
void PPPoEInit(IPInterface* interface, const char* serviceName);
BOOL PPPoEOpen(IPInterface* interface);
void PPPoETerminate(IPInterface* interface);
void PPPoEIn(IPInterface* interface, ETHHeader* eh, s32 len, u32 flag);
int PPPoEGetACName(IPInterface* interface, char* acname);

#ifdef __cplusplus
}
#endif

#endif
