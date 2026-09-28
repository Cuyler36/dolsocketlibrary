#include <dolphin/ip.h>
#include <dolphin/ip/IPArp.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static DHCPControl Control; // size: 0x938, address: 0x0
static IPInterfaceConf Conf; // size: 0x40, address: 0x938
static u8 MagicCookie[4] = { 99, 130, 83, 99 }; // size: 0x4, address: 0x0
static char* TypeNames[8] = {
    "(None)",
    "DISCOVER",
    "OFFER",
    "REQUEST",
    "DECLINE",
    "ACK",
    "NAK",
    "RELEASE",
}; // size: 0x20, address: 0xC

static s32 DHCPDiscover(DHCPControl* ctrl);
static s32 DHCPRequest(DHCPControl* ctrl);
static void Start(DHCPControl* ctrl);
static void Stop(DHCPControl* ctrl);
static void Claim(DHCPControl* ctrl);
static int Restart(DHCPControl* ctrl, s64 wait);

// Range: 0x0 -> 0x3C8
void DHCPDump(DHCPHeader* dhcp /* r30 */, s32 optlen /* r27 */) {
    // Local variables
    u8 type; // r24
    u8* opt; // r31
    s32 len; // r28
    u8* sname; // r26
    u8* file; // r25

    // References
    // -> static char * TypeNames[8];
    // -> static unsigned char MagicCookie[4];

    sname = NULL;
    file = NULL;
    opt = (u8*)(dhcp + 1);
    if (optlen < 5 || IPNEQ(opt, MagicCookie)) {
        return;
    }
    opt += 4;
    optlen -= 4;

    OSReport("op %d, htype %d, hlen %d, hops %d, xid %u, secs %u, flags %u\n", dhcp->op, dhcp->htype, dhcp->hlen, dhcp->hops, dhcp->xid, dhcp->secs, dhcp->flags);
    OSReport("ciaddr: %d.%d.%d.%d\n", dhcp->ciaddr[0], dhcp->ciaddr[1], dhcp->ciaddr[2], dhcp->ciaddr[3]);
    OSReport("yiaddr: %d.%d.%d.%d\n", dhcp->yiaddr[0], dhcp->yiaddr[1], dhcp->yiaddr[2], dhcp->yiaddr[3]);
    OSReport("siaddr: %d.%d.%d.%d\n", dhcp->siaddr[0], dhcp->siaddr[1], dhcp->siaddr[2], dhcp->siaddr[3]);
    OSReport("giaddr: %d.%d.%d.%d\n", dhcp->giaddr[0], dhcp->giaddr[1], dhcp->giaddr[2], dhcp->giaddr[3]);
    OSReport("chaddr: %02x:%02x:%02x:%02x:%02x:%02x\n", dhcp->chaddr[0], dhcp->chaddr[1], dhcp->chaddr[2], dhcp->chaddr[3], dhcp->chaddr[4], dhcp->chaddr[5]);

    for (;;) {
        while (0 < optlen && *opt != 255) {
            type = *opt++;
            --optlen;
            if (type == 0) {
                (void)0;
            }
            if (optlen < 1) {
                return;
            }
            len = *opt++;
            --optlen;
            if (optlen < len) {
                return;
            }

            switch (type) {
                case 1:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: SUBNETMASK: %d.%d.%d.%d\n", opt[0], opt[1], opt[2], opt[3]);
                    break;
                case 3:
                    OSReport("DHCP: ROUTER: %d.%d.%d.%d\n", opt[0], opt[1], opt[2], opt[3]);
                    break;
                case 6:
                    if (len <= 0 || len % 4) {
                        return;
                    }
                    OSReport("DHCP: DNS1: %d.%d.%d.%d\n", opt[0], opt[1], opt[2], opt[3]);
                    if (8 <= len) {
                        OSReport("DHCP: DNS2: %d.%d.%d.%d\n", opt[4], opt[5], opt[6], opt[7]);
                    }
                    break;
                case 12:
                    OSReport("DHCP: HOST_NAME: %.*s\n", len, opt);
                    break;
                case 15:
                    OSReport("DHCP: DOMAIN_NAME: %.*s\n", len, opt);
                    break;
                case 26:
                    OSReport("DHCP: MTU: %d\n", *(u16*)opt);
                    break;
                case 28:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: BROADCAST_ADDR: %d.%d.%d.%d\n", opt[0], opt[1], opt[2], opt[3]);
                    break;
                case 51:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: LEASE_TIME: %u\n", *(u32*)opt);
                    break;
                case 52:
                    if (len != 1) {
                        return;
                    }
                    switch (*opt) {
                        case 1:
                            file = dhcp->file;
                            break;
                        case 2:
                            sname = dhcp->sname;
                            break;
                        case 3:
                            file = dhcp->file;
                            sname = dhcp->sname;
                            break;
                    }
                    break;
                case 53:
                    if (len != 1) {
                        return;
                    }
                    OSReport("DHCP: Type: %d (%s)\n", *opt, TypeNames[*opt]);
                    break;
                case 54:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: SERVER_ID: %d.%d.%d.%d\n", opt[0], opt[1], opt[2], opt[3]);
                    break;
                case 58:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: RENEWAL_TIME: %u\n", *(u32*)opt);
                    break;
                case 59:
                    if (len != 4) {
                        return;
                    }
                    OSReport("DHCP: REBINDING_TIME: %u\n", *(u32*)opt);
                    break;
            }
            opt += len;
            optlen -= len;
        }

        if (sname) {
            opt = sname;
            optlen = 64;
            sname = NULL;
        } else if (file) {
            opt = file;
            optlen = 128;
            file = NULL;
        } else {
            return;
        }
    }
}

// Range: 0x3C8 -> 0x3D0
static u32 Rotate(u32 n /* r3 */, u32 s /* r4 */) {
    return (n << s) | (n >> (32 - s));
}

// Range: 0x3D0 -> 0x4C0
static s64 DHCPBackoff(DHCPControl* ctrl /* r1+0x8 */, int n /* r30 */) {
    // Local variables
    s64 backoff; // r28
    u32 r; // r31

    ASSERTLINE(422, 0 <= n);
    if (n <= ctrl->rxmitMax) {
        n = 4 << n;
    } else {
        n = 64;
    }
    backoff = OSSecondsToTicks((s64)n);
    r = OSGetTick();
    r = Rotate(r, r % 32);
    r %= OSSecondsToTicks(2);
    return backoff + r - OSSecondsToTicks(1);
}

// Range: 0x4C0 -> 0x598
static void InitDHCPInfo(DHCPInfo* info /* r31 */) {
    // References
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPLimited[4];

    memmove(info->ipaddr, IPAddrAny, IP_ALEN);
    memmove(info->netmask, IPAddrAny, IP_ALEN);
    memmove(info->router, IPAddrAny, IP_ALEN);
    memmove(info->dns1, IPAddrAny, IP_ALEN);
    memmove(info->dns2, IPAddrAny, IP_ALEN);
    memset(info->host, 0, sizeof(info->host));
    memset(info->domain, 0, sizeof(info->domain));
    info->mtu = 0;
    memmove(info->broadcast, IPLimited, IP_ALEN);
    info->lease = 0;
    memmove(info->server, IPAddrAny, IP_ALEN);
    info->renewal = 0;
    info->rebinding = 0;
}

// Range: 0x598 -> 0x72C
static void UpdateDHCPInfo(DHCPInfo* info /* r30 */, DHCPInfo* update /* r31 */) {
    // References
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPLimited[4];

    if (IPEQ(info->ipaddr, IPAddrAny)) {
        memmove(info->ipaddr, update->ipaddr, IP_ALEN);
    }
    if (IPNEQ(update->netmask, IPAddrAny)) {
        memmove(info->netmask, update->netmask, IP_ALEN);
    }
    if (IPNEQ(update->router, IPAddrAny)) {
        memmove(info->router, update->router, IP_ALEN);
    }
    if (IPNEQ(update->dns1, IPAddrAny)) {
        memmove(info->dns1, update->dns1, IP_ALEN);
    }
    if (IPNEQ(update->dns2, IPAddrAny)) {
        memmove(info->dns2, update->dns2, IP_ALEN);
    }
    if (update->host[0]) {
        memmove(info->host, update->host, sizeof(info->host));
    }
    if (update->domain[0]) {
        memmove(info->domain, update->domain, sizeof(info->domain));
    }
    if (update->mtu) {
        info->mtu = update->mtu;
    }
    if (IPNEQ(update->broadcast, IPLimited)) {
        memmove(info->broadcast, update->broadcast, IP_ALEN);
    }
    if (update->lease) {
        info->lease = update->lease;
    }
    if (IPNEQ(update->server, IPAddrAny)) {
        memmove(info->server, update->server, IP_ALEN);
    }
    if (update->renewal) {
        info->renewal = update->renewal;
    }
    if (update->rebinding) {
        info->rebinding = update->rebinding;
    }
}

// Range: 0x72C -> 0xA90
int DHCPProcessOptions(DHCPHeader* dhcp /* r24 */, int mlen /* r1+0xC */, DHCPInfo* info /* r29 */) {
    // Local variables
    int messageType; // r23
    u8 type; // r22
    u8* opt; // r31
    s32 len; // r30
    s32 optlen; // r28
    u16 mtu; // r27
    u8* sname; // r26
    u8* file; // r25

    // References
    // -> static unsigned char MagicCookie[4];

    sname = NULL;
    file = NULL;
    opt = (u8*)(dhcp + 1);
    optlen = mlen - sizeof(DHCPHeader);
    if (optlen < 5 || IPNEQ(opt, MagicCookie)) {
        return -1;
    }
    opt += 4;
    optlen -= 4;
    messageType = -1;
    InitDHCPInfo(info);

    for (;;) {
        while (0 < optlen && *opt != 255) {
            type = *opt++;
            --optlen;
            if (type == 0) {
                (void)0;
            }
            if (optlen < 1) {
                return -1;
            }
            len = *opt++;
            --optlen;
            if (optlen < len) {
                return -1;
            }

            switch (type) {
                case 1:
                    if (len != 4) {
                        return -1;
                    }
                    memmove(info->netmask, opt, IP_ALEN);
                    break;
                case 3:
                    if (len <= 0 || len % 4) {
                        return -1;
                    }
                    memmove(info->router, opt, IP_ALEN);
                    break;
                case 6:
                    if (len <= 0 || len % 4) {
                        return -1;
                    }
                    memmove(info->dns1, opt, IP_ALEN);
                    if (8 <= len) {
                        memmove(info->dns2, opt + 4, IP_ALEN);
                    }
                    break;
                case 12:
                    memmove(info->host, opt, len);
                    info->host[len] = '\0';
                    break;
                case 15:
                    memmove(info->domain, opt, len);
                    info->domain[len] = '\0';
                    break;
                case 26:
                    mtu = *(u16*)opt;
                    if (68 <= mtu) {
                        mtu = (mtu < 65535) ? mtu : 65535;
                        info->mtu = mtu;
                    }
                    break;
                case 28:
                    if (len != 4) {
                        return -1;
                    }
                    memmove(info->broadcast, opt, IP_ALEN);
                    break;
                case 51:
                    if (len != 4) {
                        return -1;
                    }
                    info->lease = *(u32*)opt;
                    break;
                case 52:
                    if (len != 1) {
                        return -1;
                    }
                    switch (*opt) {
                        case 1:
                            file = dhcp->file;
                            break;
                        case 2:
                            sname = dhcp->sname;
                            break;
                        case 3:
                            file = dhcp->file;
                            sname = dhcp->sname;
                            break;
                    }
                    break;
                case 53:
                    if (len != 1) {
                        return -1;
                    }
                    messageType = *opt;
                    break;
                case 54:
                    if (len != 4) {
                        return -1;
                    }
                    memmove(info->server, opt, IP_ALEN);
                    break;
                case 58:
                    if (len != 4) {
                        return -1;
                    }
                    info->renewal = *(u32*)opt;
                    break;
                case 59:
                    if (len != 4) {
                        return -1;
                    }
                    info->rebinding = *(u32*)opt;
                    break;
            }
            opt += len;
            optlen -= len;
        }

        if (sname) {
            opt = sname;
            optlen = 64;
            sname = NULL;
        } else if (file) {
            opt = file;
            optlen = 128;
            file = NULL;
        } else {
            break;
        }
    }

    memmove(info->ipaddr, dhcp->yiaddr, IP_ALEN);
    return messageType;
}

// Range: 0xA90 -> 0xB30
static u8* AddRequestList(u8* opt /* r3 */) {
    // Local variables
    u8* ptr; // r31

    ptr = opt;
    *ptr++ = 55;
    *ptr++ = 2;
    *ptr++ = 1;
    *ptr++ = 3;
    *ptr++ = 6;
    *ptr++ = 12;
    *ptr++ = 15;
    *ptr++ = 28;
    *ptr++ = 58;
    *ptr++ = 59;
    opt[1] = ptr - opt - 2;
    return ptr;
}

// Range: 0xB30 -> 0xDC8
static void RecvCallback(UDPInfo* info /* r1+0x8 */, s32 result /* r1+0xC */) {
    // Local variables
    DHCPControl* ctrl; // r31
    DHCPHeader* dhcp; // r30
    int type; // r29

    // References
    // -> struct IPInterface __IFDefault;

    ctrl = (DHCPControl*)info;
    dhcp = (DHCPHeader*)ctrl->heap;
    if (241 <= result && dhcp->xid == ctrl->xid && dhcp->htype == 1 && dhcp->hlen == 6 &&
        memcmp(dhcp->chaddr, __IFDefault.mac, 6) == 0 && 0 <= (type = DHCPProcessOptions(dhcp, ctrl->udp.len, &ctrl->tempInfo))) {
        switch (ctrl->state) {
            case 1:
                if (type == 2 && ctrl->tempInfo.lease != 0) {
                    memmove(&ctrl->info, &ctrl->tempInfo, sizeof(DHCPInfo));
                    ctrl->rxmitCount = 0;
                    ctrl->state = 2;
                    ctrl->callback(ctrl->state);
                    ctrl->xid++;
                    DHCPRequest(ctrl);
                    return;
                }
                break;
            case 2:
                switch (type) {
                    case 5:
                        if (ctrl->tempInfo.lease != 0) {
                            UpdateDHCPInfo(&ctrl->info, &ctrl->tempInfo);
                            Claim(ctrl);
                        }
                        return;
                    case 6:
                        Stop(ctrl);
                        IPSetConfigError(NULL, -102);
                        return;
                }
                break;
            case 3:
                break;
            case 4:
            case 5:
                switch (type) {
                    case 5:
                        if (ctrl->tempInfo.lease != 0) {
                            UpdateDHCPInfo(&ctrl->info, &ctrl->tempInfo);
                            Start(ctrl);
                        }
                        return;
                    case 6:
                        Stop(ctrl);
                        IPSetConfigError(NULL, -102);
                        return;
                }
                break;
            case 7:
                switch (type) {
                    case 5:
                        if (ctrl->tempInfo.lease != 0) {
                            UpdateDHCPInfo(&ctrl->info, &ctrl->tempInfo);
                            Claim(ctrl);
                        }
                        return;
                    case 6:
                        Stop(ctrl);
                        IPSetConfigError(NULL, -102);
                        if (!(ctrl->flag & 2)) {
                            Restart(ctrl, OSSecondsToTicks(300LL));
                        }
                        return;
                }
                break;
        }
    }

    UDPReceiveAsync(&ctrl->udp, ctrl->heap, sizeof(ctrl->heap), NULL, &ctrl->socket, RecvCallback, NULL);
}

// Range: 0xDC8 -> 0xE2C
static void T1Handler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)((u8*)alarm - offsetof(DHCPControl, t1));
    ctrl->state = 4;
    ctrl->callback(ctrl->state);
    ctrl->xid++;
    ctrl->rxmitCount = 0;
    DHCPRequest(ctrl);
}

// Range: 0xE2C -> 0xE90
static void T2Handler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)((u8*)alarm - offsetof(DHCPControl, t2));
    ctrl->state = 5;
    ctrl->callback(ctrl->state);
    ctrl->xid++;
    ctrl->rxmitCount = 0;
    DHCPRequest(ctrl);
}

// Range: 0xE90 -> 0xED4
static void ExHandler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)((u8*)alarm - offsetof(DHCPControl, expire));
    IPSetConfigError(NULL, -101);
    Stop(ctrl);
}

// Range: 0xED4 -> 0xFF0
static void RxmitHandler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)((u8*)alarm - offsetof(DHCPControl, rxmitAlarm));
    ctrl->rxmitCount++;
    if (ctrl->rxmitCount == ctrl->rxmitMax) {
        switch (ctrl->state) {
            case 1:
            case 2:
                IPSetConfigError(NULL, -100);
                Stop(ctrl);
                return;
                break;
            case 4:
            case 5:
                return;
            case 7:
                ctrl->state = 3;
                ctrl->callback(ctrl->state);
                return;
            case 3:
            case 6:
                break;
        }
    }

    if (ctrl->rxmitMax <= ctrl->rxmitCount) {
        ctrl->rxmitCount = ctrl->rxmitMax;
    }

    switch (ctrl->state) {
        case 1:
            DHCPDiscover(ctrl);
            break;
        case 2:
        case 4:
        case 5:
        case 7:
            DHCPRequest(ctrl);
            break;
        case 3:
            break;
    }
}

// Range: 0xFF0 -> 0x1024
static void ReleaseCallback(UDPInfo* info /* r1+0x8 */, s32) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)info;
    Stop(ctrl);
}

// Range: 0x1024 -> 0x105C
static void ReleaseHandler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    DHCPControl* ctrl; // r31

    ctrl = (DHCPControl*)((u8*)alarm - offsetof(DHCPControl, rxmitAlarm));
    Stop(ctrl);
}

// Range: 0x105C -> 0x131C
static s32 DHCPDiscover(DHCPControl* ctrl /* r31 */) {
    // Local variables
    DHCPHeader* dhcp; // r29
    u8* opt; // r30
    IPSocket socket; // r1+0xC
    s32 result; // r27
    u32 len; // r28

    // References
    // -> unsigned char IPLimited[4];
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char MagicCookie[4];

    if (ctrl->state != 1) {
        return -12;
    }

    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);

    opt = ctrl->heap + sizeof(DHCPHeader);
    memmove(opt, MagicCookie, 4);
    opt += 4;
    *opt++ = 53;
    *opt++ = 1;
    *opt++ = 1;
    *opt++ = 61;
    *opt++ = 7;
    *opt++ = 1;
    memmove(opt, __IFDefault.mac, 6);
    opt += 6;
    opt = AddRequestList(opt);
    if (ctrl->hostName[0]) {
        len = strlen(ctrl->hostName);
        ASSERTLINE(1006, len <= 255);
        *opt++ = 12;
        *opt++ = len;
        memmove(opt, ctrl->hostName, len);
        opt += len;
    }
    *opt++ = 255;
    ctrl->len = opt - ctrl->heap;
    if (ctrl->len < 300) {
        memset(opt, 0, 300 - ctrl->len);
        ctrl->len = 300;
    }

    dhcp = (DHCPHeader*)ctrl->heap;
    dhcp->op = 1;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = ctrl->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
    memset(dhcp->ciaddr, 0, IP_ALEN);
    memset(dhcp->yiaddr, 0, IP_ALEN);
    memset(dhcp->siaddr, 0, IP_ALEN);
    memset(dhcp->giaddr, 0, IP_ALEN);
    memmove(dhcp->chaddr, __IFDefault.mac, 6);
    memset(dhcp->sname, 0, sizeof(dhcp->sname));
    memset(dhcp->file, 0, sizeof(dhcp->file));

    socket.len = IP_SOCKLEN;
    socket.family = IP_INET;
    memmove(socket.addr, IPLimited, IP_ALEN);
    socket.port = 67;
    result = UDPSendAsync(&ctrl->udp, ctrl->heap, ctrl->len, &socket, NULL, NULL);
    OSSetAlarm(&ctrl->rxmitAlarm, DHCPBackoff(ctrl, ctrl->rxmitCount), RxmitHandler);
    UDPReceiveAsync(&ctrl->udp, ctrl->heap, sizeof(ctrl->heap), NULL, &ctrl->socket, RecvCallback, NULL);
    return result;
}

// Range: 0x131C -> 0x15C0
static s32 DHCPDecline(DHCPControl* ctrl /* r30 */) {
    // Local variables
    DHCPHeader* dhcp; // r29
    u8* opt; // r31
    IPSocket socket; // r1+0xC

    // References
    // -> unsigned char IPLimited[4];
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char MagicCookie[4];

    if (ctrl->state != 2 && ctrl->state != 7 && ctrl->state != 4 && ctrl->state != 5) {
        return -12;
    }

    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);

    opt = ctrl->heap + sizeof(DHCPHeader);
    memmove(opt, MagicCookie, 4);
    opt += 4;
    *opt++ = 53;
    *opt++ = 1;
    *opt++ = 4;
    *opt++ = 54;
    *opt++ = 4;
    memmove(opt, ctrl->info.server, IP_ALEN);
    opt += 4;
    *opt++ = 50;
    *opt++ = 4;
    memmove(opt, ctrl->info.ipaddr, IP_ALEN);
    opt += 4;
    *opt++ = 61;
    *opt++ = 7;
    *opt++ = 1;
    memmove(opt, __IFDefault.mac, 6);
    opt += 6;
    *opt++ = 255;
    ctrl->len = opt - ctrl->heap;
    if (ctrl->len < 300) {
        memset(opt, 0, 300 - ctrl->len);
        ctrl->len = 300;
    }

    dhcp = (DHCPHeader*)ctrl->heap;
    dhcp->op = 1;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = ctrl->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
    memset(dhcp->ciaddr, 0, IP_ALEN);
    memset(dhcp->yiaddr, 0, IP_ALEN);
    memset(dhcp->siaddr, 0, IP_ALEN);
    memset(dhcp->giaddr, 0, IP_ALEN);
    memmove(dhcp->chaddr, __IFDefault.mac, 6);
    memset(dhcp->sname, 0, sizeof(dhcp->sname));
    memset(dhcp->file, 0, sizeof(dhcp->file));

    OSSetAlarm(&ctrl->rxmitAlarm, DHCPBackoff(ctrl, ctrl->rxmitCount), ReleaseHandler);
    socket.len = IP_SOCKLEN;
    socket.family = IP_INET;
    memmove(socket.addr, IPLimited, IP_ALEN);
    socket.port = 67;
    return UDPSendAsync(&ctrl->udp, ctrl->heap, ctrl->len, &socket, ReleaseCallback, NULL);
}

// Range: 0x15C0 -> 0x182C
static s32 DHCPRelease(DHCPControl* ctrl /* r31 */) {
    // Local variables
    DHCPHeader* dhcp; // r29
    u8* opt; // r30
    IPSocket socket; // r1+0xC

    // References
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char MagicCookie[4];

    if (ctrl->state != 3 && ctrl->state != 4 && ctrl->state != 5) {
        return -12;
    }

    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);

    opt = ctrl->heap + sizeof(DHCPHeader);
    memmove(opt, MagicCookie, 4);
    opt += 4;
    *opt++ = 53;
    *opt++ = 1;
    *opt++ = 7;
    *opt++ = 54;
    *opt++ = 4;
    memmove(opt, ctrl->info.server, IP_ALEN);
    opt += 4;
    *opt++ = 61;
    *opt++ = 7;
    *opt++ = 1;
    memmove(opt, __IFDefault.mac, 6);
    opt += 6;
    *opt++ = 255;
    ctrl->len = opt - ctrl->heap;
    if (ctrl->len < 300) {
        memset(opt, 0, 300 - ctrl->len);
        ctrl->len = 300;
    }

    dhcp = (DHCPHeader*)ctrl->heap;
    dhcp->op = 1;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = ctrl->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
    memmove(dhcp->ciaddr, ctrl->info.ipaddr, IP_ALEN);
    memset(dhcp->yiaddr, 0, IP_ALEN);
    memset(dhcp->siaddr, 0, IP_ALEN);
    memset(dhcp->giaddr, 0, IP_ALEN);
    memmove(dhcp->chaddr, __IFDefault.mac, 6);
    memset(dhcp->sname, 0, sizeof(dhcp->sname));
    memset(dhcp->file, 0, sizeof(dhcp->file));

    OSSetAlarm(&ctrl->rxmitAlarm, DHCPBackoff(ctrl, ctrl->rxmitCount), ReleaseHandler);
    socket.len = IP_SOCKLEN;
    socket.family = IP_INET;
    memmove(socket.addr, ctrl->info.server, IP_ALEN);
    socket.port = 67;
    return UDPSendAsync(&ctrl->udp, ctrl->heap, ctrl->len, &socket, ReleaseCallback, NULL);
}

// Range: 0x182C -> 0x1D3C
static s32 DHCPRequest(DHCPControl* ctrl /* r31 */) {
    // Local variables
    DHCPHeader* dhcp; // r29
    u8* opt; // r30
    IPSocket socket; // r1+0xC
    s32 result; // r25
    s64 backoff; // r27
    u32 len; // r26

    // References
    // -> unsigned char IPLimited[4];
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char MagicCookie[4];

    if (ctrl->state != 2 && ctrl->state != 7 && ctrl->state != 4 && ctrl->state != 5) {
        return -12;
    }

    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);

    opt = ctrl->heap + sizeof(DHCPHeader);
    memmove(opt, MagicCookie, 4);
    opt += 4;
    *opt++ = 53;
    *opt++ = 1;
    *opt++ = 3;
    if (ctrl->state == 2) {
        *opt++ = 54;
        *opt++ = 4;
        memmove(opt, ctrl->info.server, IP_ALEN);
        opt += 4;
    }
    if (ctrl->state == 2 || ctrl->state == 7) {
        *opt++ = 50;
        *opt++ = 4;
        memmove(opt, ctrl->info.ipaddr, IP_ALEN);
        opt += 4;
    }
    *opt++ = 61;
    *opt++ = 7;
    *opt++ = 1;
    memmove(opt, __IFDefault.mac, 6);
    opt += 6;
    opt = AddRequestList(opt);
    if (ctrl->hostName[0]) {
        len = strlen(ctrl->hostName);
        ASSERTLINE(1323, len <= 255);
        *opt++ = 12;
        *opt++ = len;
        memmove(opt, ctrl->hostName, len);
        opt += len;
    }
    *opt++ = 255;
    ctrl->len = opt - ctrl->heap;
    if (ctrl->len < 300) {
        memset(opt, 0, 300 - ctrl->len);
        ctrl->len = 300;
    }

    dhcp = (DHCPHeader*)ctrl->heap;
    if (ctrl->state == 4 || ctrl->state == 5) {
        memmove(dhcp->ciaddr, ctrl->info.ipaddr, IP_ALEN);
    } else {
        memset(dhcp->ciaddr, 0, IP_ALEN);
    }
    dhcp->op = 1;
    dhcp->htype = 1;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = ctrl->xid;
    dhcp->secs = 0;
    dhcp->flags = 0;
    memset(dhcp->yiaddr, 0, IP_ALEN);
    memset(dhcp->siaddr, 0, IP_ALEN);
    memset(dhcp->giaddr, 0, IP_ALEN);
    memmove(dhcp->chaddr, __IFDefault.mac, 6);
    memset(dhcp->sname, 0, sizeof(dhcp->sname));
    memset(dhcp->file, 0, sizeof(dhcp->file));

    socket.len = IP_SOCKLEN;
    socket.family = IP_INET;
    if (ctrl->state == 4) {
        memmove(socket.addr, ctrl->info.server, IP_ALEN);
    } else {
        memmove(socket.addr, IPLimited, IP_ALEN);
    }
    socket.port = 67;

    switch (ctrl->state) {
        case 2:
        case 7:
            backoff = DHCPBackoff(ctrl, ctrl->rxmitCount);
            break;
        case 4:
            ctrl->rxmitCount = 0;
            backoff = (ctrl->t2Time - OSGetTime()) / 2;
            if (backoff <= OSSecondsToTicks(60LL)) {
                ctrl->rxmitCount = ctrl->rxmitMax - 1;
            }
            break;
        case 5:
            ctrl->rxmitCount = 0;
            backoff = (ctrl->expireTime - OSGetTime()) / 2;
            if (backoff <= OSSecondsToTicks(60LL)) {
                ctrl->rxmitCount = ctrl->rxmitMax - 1;
            }
            break;
        case 3:
            break;
    }

    result = UDPSendAsync(&ctrl->udp, ctrl->heap, ctrl->len, &socket, NULL, NULL);
    OSSetAlarm(&ctrl->rxmitAlarm, backoff, RxmitHandler);
    UDPReceiveAsync(&ctrl->udp, ctrl->heap, sizeof(ctrl->heap), NULL, &ctrl->socket, RecvCallback, NULL);
    return result;
}

// Range: 0x1D3C -> 0x2030
static void Start(DHCPControl* ctrl /* r31 */) {
    // Local variables
    DHCPInfo* info; // r30
    u32 renewal; // r29
    u32 rebinding; // r28
    u32 lease; // r27
    s64 t; // r25
    s32 mtu; // r1+0xC

    // References
    // -> struct IPInterface __IFDefault;

    info = &ctrl->info;
    ASSERTLINE(1428, info->lease != 0);

    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);
    ctrl->rxmitCount = 0;
    OSCancelAlarm(&ctrl->t1);
    OSCancelAlarm(&ctrl->t2);
    OSCancelAlarm(&ctrl->expire);

    lease = info->lease;
    renewal = info->renewal;
    if (renewal == 0 || lease <= renewal) {
        renewal = lease / 2;
    }
    rebinding = info->rebinding;
    if (rebinding == 0 || lease <= rebinding) {
        rebinding = (u64)lease * 7 / 8;
    }
    if (rebinding <= renewal) {
        renewal = (u64)rebinding * 8 / 14;
    }
    if (10 < renewal) {
        renewal -= 10;
        rebinding -= 10;
        lease -= 10;
    }

    t = OSGetTime();
    ctrl->t2Time = t + OSSecondsToTicks((s64)rebinding);
    ctrl->expireTime = t + OSSecondsToTicks((s64)lease);
    OSSetAlarm(&ctrl->t1, OSSecondsToTicks((s64)renewal), T1Handler);
    OSSetAlarm(&ctrl->t2, OSSecondsToTicks((s64)rebinding), T2Handler);
    OSSetAlarm(&ctrl->expire, OSSecondsToTicks((s64)lease), ExHandler);

    IPInitRoute(info->ipaddr, info->netmask, info->router);
    IPSetBroadcastAddr(&__IFDefault, info->broadcast);
    if (68 <= info->mtu) {
        IPGetMtu(&__IFDefault, &mtu);
        mtu = (info->mtu < mtu) ? info->mtu : mtu;
        IPSetMtu(&__IFDefault, mtu);
    }

    ctrl->state = 3;
    ctrl->callback(ctrl->state);
}

// Range: 0x2030 -> 0x2148
static void Stop(DHCPControl* ctrl /* r31 */) {
    // References
    // -> static struct IPInterfaceConf Conf;
    // -> struct IPInterface __IFDefault;
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPLimited[4];

    if (ctrl->state == 0) {
        return;
    }

    ctrl->state = 0;
    UDPClose(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);
    ctrl->rxmitCount = 0;
    OSCancelAlarm(&ctrl->t1);
    OSCancelAlarm(&ctrl->t2);
    OSCancelAlarm(&ctrl->expire);
    ctrl->flag &= ~4;

    IPInitRoute(NULL, NULL, NULL);
    IPSetBroadcastAddr(&__IFDefault, IPLimited);
    memcpy(Conf.addr, IPAddrAny, IP_ALEN);
    ARPClaim(&__IFDefault, &Conf);
    ctrl->callback(ctrl->state);

    if (ctrl->flag & 2) {
        Restart(ctrl, OSSecondsToTicks(300LL));
    }
}

// Range: 0x2148 -> 0x2218
static void ClaimHandler(IPInterfaceConf* conf /* r30 */, s32 result /* r1+0xC */) {
    // Local variables
    DHCPControl* ctrl; // r31

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    memset(conf->addr, 0, IP_ALEN);
    ARPClaim(conf->interface, conf);
    if (result == 0) {
        Start(&Control);
    } else {
        OSCancelAlarm(&ctrl->rxmitAlarm);
        ctrl->rxmitCount = 0;
        OSCancelAlarm(&ctrl->t1);
        OSCancelAlarm(&ctrl->t2);
        OSCancelAlarm(&ctrl->expire);
        ctrl->flag |= 4;
        ctrl->xid++;
        if (DHCPDecline(ctrl) < 0) {
            Stop(ctrl);
        }
        IPSetConfigError(conf->interface, -111);
    }
}

// Range: 0x2218 -> 0x22A0
static void Claim(DHCPControl* ctrl /* r31 */) {
    // Local variables
    DHCPInfo* info; // r30

    // References
    // -> static struct IPInterfaceConf Conf;
    // -> struct IPInterface __IFDefault;

    info = &ctrl->info;
    UDPCancel(&ctrl->udp);
    OSCancelAlarm(&ctrl->rxmitAlarm);
    ctrl->rxmitCount = 0;
    OSCancelAlarm(&ctrl->t1);
    OSCancelAlarm(&ctrl->t2);
    OSCancelAlarm(&ctrl->expire);
    memcpy(Conf.addr, info->ipaddr, IP_ALEN);
    ARPClaim(&__IFDefault, &Conf);
}

// Range: 0x22A0 -> 0x23B0
static int Restart(DHCPControl* ctrl /* r31 */, s64 wait /* r1+0x10 */) {
    // Local variables
    IPSocket socket; // r1+0x18

    // References
    // -> unsigned char IPAddrAny[4];

    if (ctrl->state != 0) {
        return FALSE;
    }

    ctrl->state = 1;
    ctrl->callback(ctrl->state);
    ctrl->xid++;
    UDPOpen(&ctrl->udp, NULL, 0);
    socket.len = IP_SOCKLEN;
    socket.family = IP_INET;
    memmove(socket.addr, IPAddrAny, IP_ALEN);
    socket.port = 68;
    if (UDPBind(&ctrl->udp, &socket) < 0) {
        return FALSE;
    }

    switch (ctrl->state) {
        case 1:
            ctrl->rxmitCount = -1;
            OSCancelAlarm(&ctrl->rxmitAlarm);
            OSSetAlarm(&ctrl->rxmitAlarm, wait, RxmitHandler);
            break;
        case 2:
            DHCPRequest(ctrl);
            break;
    }
    return TRUE;
}

// Range: 0x23B0 -> 0x23B4
static void NullCallback() {}

// Range: 0x23B4 -> 0x24C4
int DHCPStartupEx(void (*callback)(int) /* r25 */, int rxmitMax /* r26 */, const char* hostName /* r27 */) {
    // Local variables
    DHCPControl* ctrl; // r31
    int enabled; // r29
    int rc; // r28

    // References
    // -> static struct IPInterfaceConf Conf;
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    enabled = OSDisableInterrupts();
    if (!(ctrl->flag & 1)) {
        memset(ctrl, 0, sizeof(DHCPControl));
        ctrl->flag |= 3;
        ctrl->rxmitMax = (rxmitMax <= 0) ? 4 : rxmitMax;
        if (hostName) {
            strncpy(ctrl->hostName, hostName, sizeof(ctrl->hostName));
        }
        ctrl->xid = OSGetTick();
        OSCreateAlarm(&Conf.alarm);
        Conf.callback = (void (*)(void*, s32))ClaimHandler;
    }
    ctrl->callback = callback ? callback : NullCallback;
    rc = Restart(ctrl, OSSecondsToTicks(1) + OSGetTick() % OSSecondsToTicks(1));
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x24C4 -> 0x24F4
int DHCPStartup(void (*callback)(int) /* r1+0x8 */) {
    return DHCPStartupEx(callback, 4, NULL);
}

// Range: 0x24F4 -> 0x25C4
int DHCPCleanup(void) {
    // Local variables
    DHCPControl* ctrl; // r31
    int enabled; // r29
    int rc; // r30

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    enabled = OSDisableInterrupts();
    if (ctrl->flag & 1) {
        DHCPAuto(FALSE);
        if (ctrl->state != 0 && !(ctrl->flag & 4)) {
            OSCancelAlarm(&ctrl->rxmitAlarm);
            ctrl->rxmitCount = 0;
            OSCancelAlarm(&ctrl->t1);
            OSCancelAlarm(&ctrl->t2);
            OSCancelAlarm(&ctrl->expire);
            ctrl->flag |= 4;
            ctrl->xid++;
            if (DHCPRelease(ctrl) < 0) {
                Stop(ctrl);
            }
        }
        rc = TRUE;
    } else {
        rc = FALSE;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x25C4 -> 0x2648
int DHCPReboot(void) {
    // Local variables
    DHCPControl* ctrl; // r31

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    switch (ctrl->state) {
        case 3:
        case 4:
        case 5:
            ctrl->state = 7;
            ctrl->callback(ctrl->state);
            ctrl->rxmitCount = 0;
            ctrl->xid++;
            DHCPRequest(ctrl);
            return TRUE;
    }
    return FALSE;
}

// Range: 0x2648 -> 0x2704
int DHCPAuto(int enable /* r1+0x8 */) {
    // Local variables
    DHCPControl* ctrl; // r31
    int prev; // r30
    int enabled; // r29

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    enabled = OSDisableInterrupts();
    prev = (ctrl->flag & 2) ? TRUE : FALSE;
    if (enable) {
        ctrl->flag |= 2;
        Restart(ctrl, OSSecondsToTicks(300LL));
    } else {
        ctrl->flag &= ~2;
    }
    OSRestoreInterrupts(enabled);
    return prev;
}

// Range: 0x2704 -> 0x2764
int DHCPGetStatus(DHCPInfo* info /* r28 */) {
    // Local variables
    DHCPControl* ctrl; // r31
    int enabled; // r30
    int state; // r29

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    enabled = OSDisableInterrupts();
    state = ctrl->state;
    if (info) {
        memmove(info, &ctrl->info, sizeof(DHCPInfo));
    }
    OSRestoreInterrupts(enabled);
    return state;
}

// Range: 0x2764 -> 0x2960
int DHCPGetOpt(int opt /* r1+0x8 */, void* buf /* r29 */, int len /* r28 */) {
    // Local variables
    DHCPControl* ctrl; // r30
    u32 ulen; // r31

    // References
    // -> static struct DHCPControl Control;

    ctrl = &Control;
    if (len < 0) {
        len = 0;
    }
    ulen = len;
    switch (opt) {
        case 1:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, ctrl->info.netmask, ulen);
            break;
        case 3:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, ctrl->info.router, ulen);
            break;
        case 6:
            ulen = (ulen > 8) ? 8 : ulen;
            memmove(buf, ctrl->info.dns1, ulen);
            break;
        case 12:
            ulen = (strlen(ctrl->info.host) < ulen) ? strlen(ctrl->info.host) : ulen;
            strncpy(buf, ctrl->info.host, ulen);
            break;
        case 15:
            ulen = (strlen(ctrl->info.domain) < ulen) ? strlen(ctrl->info.domain) : ulen;
            strncpy(buf, ctrl->info.domain, ulen);
            break;
        case 26:
            ulen = (ulen > 2) ? 2 : ulen;
            memmove(buf, &ctrl->info.mtu, ulen);
            break;
        case 28:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, ctrl->info.broadcast, ulen);
            break;
        case 51:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, &ctrl->info.lease, ulen);
            break;
        case 54:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, ctrl->info.server, ulen);
            break;
        case 58:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, &ctrl->info.renewal, ulen);
            break;
        case 59:
            ulen = (ulen > 4) ? 4 : ulen;
            memmove(buf, &ctrl->info.rebinding, ulen);
            break;
    }
    return ulen;
}
