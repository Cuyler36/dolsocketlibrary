#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

#define IGMP_TABLE_SIZE 4

const u8 IPAllHosts[4] = { 224, 0, 0, 1 }; // size: 0x4, address: 0x0
static IGMPInfo IgmpTable[IGMP_TABLE_SIZE]; // size: 0xE0, address: 0x0

// Range: 0x0 -> 0x88
BOOL IPJoinLocalGroup(IPInterface* interface /* r1+0x8 */, const u8* groupAddr /* r31 */) {
    // Local variables
    u8 mac[6]; // r1+0x10

    switch (interface->type) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
            mac[0] = 0x01;
            mac[1] = 0x00;
            mac[2] = 0x5E;
            mac[3] = groupAddr[1] & 0x7F;
            mac[4] = groupAddr[2];
            mac[5] = groupAddr[3];
            ETHAddMulticastAddress(mac);
            break;
    }
    return TRUE;
}

// Range: 0x88 -> 0x90
BOOL IPLeaveLocalGroup() {
    return TRUE;
}

// Range: 0x90 -> 0xE4
u16 IGMPCheckSum(IGMP* igmp /* r3 */) {
    // Local variables
    u32 sum; // r31
    u16* p; // r30

    sum = 0;
    for (p = (u16*)igmp; p < (u16*)((u8*)igmp + sizeof(IGMP)); p++) {
        sum += *p;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return sum ^ 0xFFFF;
}

// Range: 0xE4 -> 0x1F0
static s64 GetRandomValue(u8* addr /* r1+0x8 */) {
    // Local variables
    s64 tick; // r30

    tick = OSGetTime();
    tick += IPU32(addr);
    tick = OSMicrosecondsToTicks(tick);
    tick %= OSSecondsToTicks((s64)10);
    return (tick >= 0) ? tick : -tick;
}

// Range: 0x1F0 -> 0x25C
IGMPInfo* IGMPLookupInfo(u8* groupAddr /* r3 */) {
    // Local variables
    IGMPInfo* info; // r31

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAddrAny[4];
    if (IPEQ(groupAddr, IPAddrAny)) {
        return NULL;
    }

    for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
        if (IPEQ(groupAddr, info->addr)) {
            return info;
        }
    }
    return NULL;
}

// Range: 0x25C -> 0x43C
static void IGMPOut(u8 type /* r25 */, u8* addr /* r26 */) {
    // Local variables
    IPInterface* interface; // r30
    IPHeader* ip; // r31
    IGMP* igmp; // r28
    IFDatagram* datagram; // r29
    IGMPInfo* info; // r27

    // References
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPAllHosts[4];
    // -> struct IPInterface __IFDefault;
    interface = &__IFDefault;
    info = IGMPLookupInfo(addr);
    if (info == NULL) {
        return;
    }

    datagram = (IFDatagram*)interface->alloc(interface, sizeof(IFDatagram) + sizeof(IPHeader) + sizeof(IGMP));
    if (datagram == NULL) {
        return;
    }

    IFInitDatagram(datagram, ETH_IP, 1);
    ip = (IPHeader*)(datagram + 1);
    igmp = (IGMP*)(ip + 1);

    ip->verlen = 0x45;
    ip->tos = 0;
    ip->len = IP_HLEN(ip) + sizeof(IGMP);
    ip->ttl = 1;
    ip->proto = IP_PROTO_IGMP;
    ip->frag = 0;

    igmp->vertype = 0x10 | (type & 0xF);
    igmp->unused = 0;
    switch (type) {
        case 1:
            memmove(igmp->addr, IPAddrAny, IP_ALEN);
            memmove(ip->dst, IPAllHosts, IP_ALEN);
            break;
        case 2:
            memmove(igmp->addr, addr, IP_ALEN);
            memmove(ip->dst, addr, IP_ALEN);
            break;
        default:
            OSPanic(__FILE__, 176, "IGMPOut() fatal error.");
            break;
    }

    if (IPNEQ(info->interface, IPAddrAny)) {
        memmove(ip->src, info->interface, IP_ALEN);
    } else if (IPEQ(interface->addr, IPAddrAny)) {
        memmove(ip->src, interface->alias, IP_ALEN);
    } else {
        memmove(ip->src, interface->addr, IP_ALEN);
    }

    datagram->vec[0].data = ip;
    datagram->vec[0].len = IP_HLEN(ip) + sizeof(IGMP);
    if (IPOut(datagram) < 0) {
        interface->free(interface, datagram, sizeof(IFDatagram) + sizeof(IPHeader) + sizeof(IGMP));
    }
}

// Range: 0x43C -> 0x478
static void Timeout(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    IGMPInfo* info; // r31

    info = (IGMPInfo*)((u8*)alarm - 8);
    IGMPOut(2, info->addr);
}

// Range: 0x478 -> 0x5E8
void IGMPIn(IPInterface* interface /* r28 */, IPHeader* ip /* r30 */, u32) {
    // Local variables
    IGMPInfo* info; // r31
    IGMP* igmp; // r29

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPAllHosts[4];
    igmp = (IGMP*)((u8*)ip + IP_HLEN(ip));
    if (ip->len < IP_HLEN(ip) + (int)sizeof(IGMP) || ip->ttl != 1 || IPEQ(ip->src, interface->addr) ||
        IPEQ(ip->src, interface->alias)) {
        return;
    }

    if ((igmp->vertype >> 4) != 1) {
        return;
    }
    if (IGMPCheckSum(igmp) != 0) {
        return;
    }
    if (IPEQ(igmp->addr, IPAllHosts)) {
        return;
    }

    switch (igmp->vertype & 0xF) {
        case 1:
            if (IPNEQ(igmp->addr, IPAddrAny)) {
                break;
            }
            for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
                if (IPNEQ(info->addr, IPAddrAny) && info->alarm.handler == NULL) {
                    OSSetAlarm(&info->alarm, GetRandomValue(info->addr), Timeout);
                }
            }
            break;
        case 2:
            info = IGMPLookupInfo(igmp->addr);
            if (info != NULL && IPEQ(ip->dst, info->addr)) {
                OSCancelAlarm(&info->alarm);
            }
            break;
    }
}

// Range: 0x5E8 -> 0x614
void IGMPInit(IPInterface* interface /* r1+0x8 */) {
    // References
    // -> unsigned char IPAllHosts[4];
    IPJoinLocalGroup(interface, IPAllHosts);
}

// Range: 0x614 -> 0x6A4
BOOL IGMPOnReset(BOOL final /* r1+0x8 */) {
    // Local variables
    IGMPInfo* info; // r31

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAddrAny[4];
    if (final) {
        for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
            ASSERTLINE(322, memcmp(info->addr, IPAddrAny, IP_ALEN) == 0);
        }
    }
    return TRUE;
}

// Range: 0x6A4 -> 0x748
s32 IPMulticastLookup(const u8* groupAddr /* r3 */, const u8* interface /* r4 */) {
    // Local variables
    IGMPInfo* info; // r31
    IPInterface* nic; // r1+0x10

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAllHosts[4];
    // -> struct IPInterface __IFDefault;
    nic = &__IFDefault;
    if (!IP_CLASSD(groupAddr)) {
        return -12;
    }
    if (IPEQ(groupAddr, IPAllHosts)) {
        return IGMP_TABLE_SIZE;
    }

    for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
        if (IPEQ(info->addr, groupAddr) && IPEQ(info->interface, interface)) {
            return info - IgmpTable;
        }
    }
    return -4;
}

// Range: 0x748 -> 0x8E8
s32 IPMulticastJoin(const u8* groupAddr /* r28 */, const u8* interface /* r29 */) {
    // Local variables
    IGMPInfo* info; // r31
    IGMPInfo* free; // r30
    IPInterface* nic; // r26

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPAllHosts[4];
    // -> struct IPInterface __IFDefault;
    free = NULL;
    nic = &__IFDefault;
    if (!IP_CLASSD(groupAddr)) {
        return -12;
    }
    if (IPNEQ(interface, IPAddrAny) && IPNEQ(interface, nic->addr) && IPNEQ(interface, nic->alias)) {
        return -12;
    }
    if (IPEQ(groupAddr, IPAllHosts)) {
        return IGMP_TABLE_SIZE;
    }

    for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
        if (IPEQ(info->addr, groupAddr) && IPEQ(info->interface, interface)) {
            ++info->ref;
            return info - IgmpTable;
        }
        if (free == NULL && IPEQ(info->addr, IPAddrAny)) {
            free = info;
        }
    }

    if (free == NULL) {
        return -7;
    }

    info = free;
    memmove(info->addr, groupAddr, IP_ALEN);
    memmove(info->interface, interface, IP_ALEN);
    OSCreateAlarm(&info->alarm);
    info->ref = 1;
    IPJoinLocalGroup(nic, groupAddr);
    IGMPOut(2, info->addr);
    OSSetAlarm(&info->alarm, GetRandomValue(info->addr), Timeout);
    return info - IgmpTable;
}

// Range: 0x8E8 -> 0x9CC
s32 IPMulticastLeave(const u8* groupAddr /* r29 */, const u8* interface /* r1+0xC */) {
    // Local variables
    IGMPInfo* info; // r31

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPAllHosts[4];
    if (!IP_CLASSD(groupAddr)) {
        return -12;
    }
    if (IPEQ(groupAddr, IPAllHosts)) {
        return IGMP_TABLE_SIZE;
    }

    for (info = IgmpTable; info < &IgmpTable[IGMP_TABLE_SIZE]; ++info) {
        if (IPEQ(info->addr, groupAddr) && IPEQ(info->interface, interface)) {
            info->ref--;
            if (info->ref <= 0) {
                OSCancelAlarm(&info->alarm);
                memmove(info->addr, IPAddrAny, IP_ALEN);
            }
            return info - IgmpTable;
        }
    }
    return -4;
}

// Range: 0x9CC -> 0xA78
s32 IPClose(IPInfo* info /* r28 */) {
    // Local variables
    int n; // r31
    s32 rc; // r29
    IGMPInfo* igmpInfo; // r30

    // References
    // -> static struct IGMPInfo IgmpTable[4];
    for (n = 0; n < IGMP_TABLE_SIZE; n++) {
        if (info->flag & (1 << n)) {
            igmpInfo = &IgmpTable[n];
            rc = IPMulticastLeave(igmpInfo->addr, igmpInfo->interface);
            ASSERTLINE(463, n == rc);
            info->flag &= ~(1 << n);
        }
    }
    return 0;
}
