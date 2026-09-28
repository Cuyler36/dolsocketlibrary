#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

static void DoNotify(IPHeader* org, u8* gateway, s32 err);

// Range: 0x0 -> 0x68
static int ICMPIsErrorMessage(u8 type /* r3 */) {
    switch (type) {
        case 3:
            return sizeof(ICMPUnreachable);
        case 4:
            return sizeof(ICMPUnreachable);
        case 5:
            return sizeof(ICMPRedirect);
        case 11:
            return sizeof(ICMPUnreachable);
        case 12:
            return sizeof(ICMPUnreachable);
        default:
            return 0;
    }
}

// Range: 0x68 -> 0xBC
static u16 ICMPCheckSum(ICMPHeader* ip /* r3 */, int len /* r4 */) {
    // Local variables
    u32 sum; // r31
    u16* p; // r30

    sum = 0;
    for (p = (u16*)ip; len > 0; len -= 2) {
        sum += *p++;
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return sum ^ 0xFFFF;
}

// Range: 0xBC -> 0x29C
static void DoEchoRequest(IPInterface* interface /* r28 */, IPHeader* ip /* r31 */, u32 flag /* r1+0x10 */) {
    // Local variables
    IFDatagram* datagram; // r29
    IPHeader* res; // r30
    ICMPHeader* icmp; // r27
    void* data; // r1+0x14

    if (ip->dst[0] == 127 || IPEQ(ip->dst, interface->addr) || IPEQ(ip->dst, interface->alias)) {
        if ((flag & 3) || IPIsBroadcastAddr(interface, ip->src) || IP_CLASSD(ip->src) || IP_CLASSE(ip->src)) {
            return;
        }

        datagram = interface->alloc(interface, ip->len + sizeof(IFDatagram));
        if (datagram == NULL) {
            return;
        }

        IFInitDatagram(datagram, ETH_IP, 1);
        datagram->vec[0].data = data = datagram + 1;
        datagram->vec[0].len = ip->len;
        res = datagram->vec[0].data;
        memmove(res, ip, IP_HLEN(ip));
        memmove(res->src, ip->dst, IP_ALEN);
        memmove(res->dst, ip->src, IP_ALEN);
        res->tos = 0;
        res->ttl = 255;
        if (IP_HLEN(res) > 20) {
            IPUpdateRecordRoute(res, res->src);
            IPReverseSourceRoute(res);
        }

        icmp = (ICMPHeader*)((u8*)res + IP_HLEN(res));
        memmove(icmp, (u8*)ip + IP_HLEN(ip), ip->len - IP_HLEN(ip));
        icmp->type = 0;
        icmp->sum = 0;
        icmp->sum = ICMPCheckSum(icmp, res->len - IP_HLEN(res));
        if (IPOut(datagram) < 0) {
            interface->free(interface, datagram, ip->len + sizeof(IFDatagram));
        }
    }
}

// Range: 0x29C -> 0x2C4
static u16 ReduceMtu(s32 mtu /* r3 */) {
    if (mtu > 1492) {
        return 1006;
    }
    if (mtu > 1006) {
        return 508;
    }
    return 68;
}

// Range: 0x2C4 -> 0x450
static void DoUnreachable(IPInterface* interface /* r26 */, IPHeader* ip /* r24 */, u32) {
    // Local variables
    ICMPUnreachable* icmp; // r29
    IPHeader* org; // r28
    u16 mtu; // r30
    IPInfo* info; // r31
    IPInfo* next; // r25
    TCPInfo* tcpInfo; // r27

    // References
    // -> IFQueue TCPInfoQueue;

    icmp = (ICMPUnreachable*)((u8*)ip + IP_HLEN(ip));
    org = (IPHeader*)(icmp + 1);
    switch (icmp->code) {
        case 4:
            if (icmp->mtu != 0) {
                mtu = (icmp->mtu < 68) ? 68 : icmp->mtu;
            } else {
                mtu = ReduceMtu((interface->mtu < org->len) ? interface->mtu : org->len);
            }
        again:
            mtu = (interface->mtu < mtu) ? interface->mtu : mtu;
            IFQueueIterator(IPInfo*, &TCPInfoQueue, info, next) {
                tcpInfo = (TCPInfo*)info;
                if (IPEQ(info->remote.addr, org->dst)) {
                    if (tcpInfo->mss < mtu - 40) {
                        mtu = ReduceMtu(tcpInfo->mss + 40);
                        goto again;
                    }
                    tcpInfo->mss = mtu - 40;
                    tcpInfo->cWin = tcpInfo->mss * 2;
                }
            }
            if (org->proto == IP_PROTO_TCP) {
                break;
            }
        case 0:
        case 1:
        case 2:
        case 3:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
            DoNotify(org, ip->src, -2);
            break;
    }
}

// Range: 0x450 -> 0x4AC
static int DoRedirect(IPInterface*, IPHeader* ip /* r30 */, u32) {
    // Local variables
    ICMPRedirect* icmp; // r31
    IPHeader* org; // r29

    icmp = (ICMPRedirect*)((u8*)ip + IP_HLEN(ip));
    org = (IPHeader*)(icmp + 1);
    if (icmp->code > 3) {
        return FALSE;
    }
    return IPRedirect(org->dst, icmp->gateway, ip->src);
}

// Range: 0x4AC -> 0x514
static void DoSourceQuench(IPHeader* org /* r31 */, u8* gateway /* r30 */) {
    switch (org->proto) {
        case IP_PROTO_UDP:
            UDPNotify(org, gateway, -18);
            break;
        case IP_PROTO_TCP:
            TCPSourceQuench(org, gateway);
            break;
    }
}

// Range: 0x514 -> 0x584
static void DoNotify(IPHeader* org /* r31 */, u8* gateway /* r29 */, s32 err /* r30 */) {
    switch (org->proto) {
        case IP_PROTO_UDP:
            UDPNotify(org, gateway, err);
            break;
        case IP_PROTO_TCP:
            TCPNotify(org, gateway, err);
            break;
    }
}

// Range: 0x584 -> 0x7C4
void ICMPIn(IPInterface* interface /* r27 */, IPHeader* ip /* r31 */, u32 flag /* r26 */) {
    // Local variables
    ICMPHeader* icmp; // r29
    IPHeader* org; // r30
    int hlen; // r28

    ASSERTLINE(355, ip->proto == IP_PROTO_ICMP);
    icmp = (ICMPHeader*)((u8*)ip + IP_HLEN(ip));
    if (ip->len < IP_HLEN(ip) + 4 || ICMPCheckSum(icmp, ip->len - IP_HLEN(ip))) {
        return;
    }

    hlen = ICMPIsErrorMessage(icmp->type);
    if (0 < hlen) {
        org = (IPHeader*)((u8*)icmp + hlen);
        if (ip->len < IP_HLEN(ip) + hlen + 28) {
            return;
        }
        if (IP_HLEN(org) < 20) {
            return;
        }
        if (ip->len < IP_HLEN(ip) + hlen + IP_HLEN(org) + 8) {
            return;
        }
        if (org->proto == IP_PROTO_ICMP) {
            return;
        }
        if (IPIsBroadcastAddr(interface, org->dst) || IP_CLASSD(org->dst) || IP_CLASSE(org->dst)) {
            return;
        }
        if (flag & 3) {
            return;
        }
        if (IP_FRAG(org)) {
            return;
        }
        if (org->src[0] == 127 || IPIsBroadcastAddr(interface, org->src) || IP_CLASSD(org->src) || IP_CLASSE(org->src)) {
            return;
        }
    } else {
        org = NULL;
    }

    switch (icmp->type) {
        case 0:
            break;
        case 3:
            DoUnreachable(interface, ip, flag);
            break;
        case 4:
            DoSourceQuench(org, ip->src);
            break;
        case 8:
            DoEchoRequest(interface, ip, flag);
            break;
        case 5:
            DoRedirect(interface, ip, flag);
            break;
        case 11:
            DoNotify(org, ip->src, -10);
            break;
        case 12:
            DoNotify(org, ip->src, -12);
            break;
    }
}

// Range: 0x7C4 -> 0xA9C
s32 ICMPSendError(ICMPHeader* icmp /* r27 */, IPInterface* interface /* r29 */, IPHeader* ip /* r31 */, u32 flag /* r1+0x14 */) {
    // Local variables
    IFDatagram* datagram; // r28
    IPHeader* res; // r30
    s32 len; // r26
    s32 rc; // r25
    void* data; // r1+0x18
    ICMPHeader* icmpRcvd; // r24

    if (icmp == NULL || !ICMPIsErrorMessage(icmp->type) || ip == NULL || IP_HLEN(ip) < 20 ||
        ip->len < IP_HLEN(ip) + 8 || (IPNEQ(ip->dst, interface->addr) && IPNEQ(ip->dst, interface->alias))) {
        return -12;
    }

    if (ip->proto == IP_PROTO_ICMP) {
        icmpRcvd = (ICMPHeader*)((u8*)ip + IP_HLEN(ip));
        if (ICMPIsErrorMessage(icmpRcvd->type)) {
            return -11;
        }
    }

    if (IPIsBroadcastAddr(interface, ip->dst) || IP_CLASSD(ip->dst) || IP_CLASSE(ip->dst)) {
        return -11;
    }
    if (flag & 3) {
        return -11;
    }
    if (IP_FRAG(ip)) {
        return -11;
    }
    if (ip->src[0] == 127 || IPIsBroadcastAddr(interface, ip->src) || IP_CLASSD(ip->src) || IP_CLASSE(ip->src)) {
        return -11;
    }

    interface = IPGetRoute(ip->src, NULL);
    if (interface == NULL) {
        return -2;
    }

    len = IP_HLEN(ip) + sizeof(IPHeader) + 8 + 8;
    datagram = interface->alloc(interface, len + sizeof(IFDatagram));
    if (datagram == NULL) {
        return -7;
    }

    IFInitDatagram(datagram, ETH_IP, 1);
    datagram->vec[0].data = data = datagram + 1;
    datagram->vec[0].len = len;
    res = datagram->vec[0].data;
    res->verlen = 0x45;
    res->tos = 0;
    res->len = len;
    res->frag = 0;
    res->ttl = 255;
    res->proto = IP_PROTO_ICMP;
    memmove(res->src, ip->dst, IP_ALEN);
    memmove(res->dst, ip->src, IP_ALEN);
    memmove((u8*)res + sizeof(IPHeader), icmp, 8);
    memmove((u8*)res + sizeof(IPHeader) + 8, ip, (u8)(IP_HLEN(ip) + 8));
    icmp = (ICMPHeader*)((u8*)res + sizeof(IPHeader));
    icmp->sum = 0;
    icmp->sum = ICMPCheckSum(icmp, res->len - IP_HLEN(res));
    rc = IPOut(datagram);
    if (rc < 0) {
        interface->free(interface, datagram, len + (s32)sizeof(IFDatagram));
    }
    return rc;
}
