#include <dolphin/ip.h>
#include <dolphin/ip/IPArp.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static u64 Seed; // size: 0x8, address: 0x0
static IPInterfaceConf Conf; // size: 0x40, address: 0x0
static s32 Collision; // size: 0x4, address: 0x8

// Range: 0x0 -> 0xC8
static void SelectAddr(u8* addr /* r30 */) {
    // Local variables
    u16 suffix; // r31

    // References
    // -> static unsigned long long Seed;
    do {
        Seed = (Seed * 0x5DEECE66DULL + 0xB) % (1ULL << 48);
        suffix = (u16)(Seed >> 32);
    } while (suffix < 0x0100 || 0xff00 <= suffix);

    if (addr) {
        addr[0] = 169;
        addr[1] = 254;
        addr[2] = (u8)(suffix >> 8);
        addr[3] = (u8)suffix;
    }
}

// Range: 0xC8 -> 0x1B4
static void ClaimHander(IPInterfaceConf* conf /* r31 */, s32 result /* r1+0xC */) {
    // References
    // -> unsigned char IPAddrAny[4];
    // -> struct IPInterface __IFDefault;
    // -> static long Collision;
    if (result == 0) {
        IPSetAlias(&__IFDefault, conf->addr);
        IPRefreshRoute();
        memset(conf->addr, 0, 4);
        ARPClaim(conf->interface, conf);
    } else {
        Collision++;
        if (Collision < 10) {
            SelectAddr(conf->addr);
            ARPClaim(conf->interface, conf);
        } else {
            SelectAddr(NULL);
            memset(conf->addr, 0, 4);
            ARPClaim(conf->interface, conf);
            if (IPNEQ(__IFDefault.alias, IPAddrAny)) {
                IPSetAlias(&__IFDefault, IPAddrAny);
                IPRefreshRoute();
            }
        }
    }
}

// Range: 0x1B4 -> 0x2CC
BOOL IPAutoConfig(void) {
    // Local variables
    BOOL enabled; // r29
    u16 suffix; // r30

    // References
    // -> static struct IPInterfaceConf Conf;
    // -> struct IPInterface __IFDefault;
    // -> static long Collision;
    // -> static unsigned long long Seed;
    enabled = OSDisableInterrupts();
    if (Seed == 0) {
        memcpy((u8*)&Seed + 2, __IFDefault.mac, 6);
        OSCreateAlarm(&Conf.alarm);
        Conf.callback = (void (*)(void*, s32))ClaimHander;
        SelectAddr(Conf.addr);
    } else {
        suffix = (u16)(Seed >> 32);
        Conf.addr[0] = 169;
        Conf.addr[1] = 254;
        Conf.addr[2] = (u8)(suffix >> 8);
        Conf.addr[3] = (u8)suffix;
        ASSERTLINE(153, !(suffix < 0x0100 || 0xff00 <= suffix));
    }
    Collision = 0;
    ARPClaim(&__IFDefault, &Conf);
    OSRestoreInterrupts(enabled);
    return TRUE;
}

// Range: 0x2CC -> 0x340
void IPAutoStop(void) {
    // Local variables
    BOOL enabled; // r31

    // References
    // -> unsigned char IPAddrAny[4];
    // -> struct IPInterface __IFDefault;
    // -> static struct IPInterfaceConf Conf;
    enabled = OSDisableInterrupts();
    memset(Conf.addr, 0, 4);
    ARPClaim(&__IFDefault, &Conf);
    IPSetAlias(&__IFDefault, IPAddrAny);
    IPRefreshRoute();
    OSRestoreInterrupts(enabled);
}
