#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

// Range: 0x0 -> 0x1D0
static int ReceiveConfigureRequest(PPPConf* conf /* r24 */, LCPHeader* lcp /* r26 */) {
    // Local variables
    u8* data; // r29
    u16 len; // r30
    LCPOpt* req; // r31
    int reject; // r27
    int nack; // r25
    u32 addr; // r28

    data = (u8*)lcp + sizeof(LCPHeader);
    len = lcp->len - sizeof(LCPHeader);
    reject = FALSE;
    nack = FALSE;
    addr = 0;

    for (req = (LCPOpt*)data; (u8*)req < data + len && !reject; req = (LCPOpt*)((u8*)req + req->len)) {
        switch (req->type) {
            case 3:
                if (req->len != 6) {
                    return -3;
                }
                addr = *(u32*)(req + 1);
                if (addr == 0) {
                    reject = TRUE;
                }
                break;
            default:
                reject = TRUE;
                break;
        }
    }

    if (reject) {
        req = (LCPOpt*)data;
        while ((u8*)req < data + len) {
            switch (req->type) {
                case 3:
                    if (addr != 0) {
                        len = PPPDeleteOpt(data, len, req);
                        continue;
                    }
                    break;
            }
            req = (LCPOpt*)((u8*)req + req->len);
        }
        lcp->len = len + 4;
        return -1;
    }

    if (nack && conf->failure <= 0) {
        req = (LCPOpt*)data;
        while ((u8*)req < data + len) {
            switch (req->type) {
                case 3:
                    if (addr != 0) {
                        len = PPPDeleteOpt(data, len, req);
                        continue;
                    }
                    break;
            }
            req = (LCPOpt*)((u8*)req + req->len);
        }
        lcp->len = len + 4;
        return -1;
    }

    if (nack) {
        req = (LCPOpt*)data;
        while ((u8*)req < data + len) {
            len = PPPDeleteOpt(data, len, req);
        }
        lcp->len = len + 4;
        return -2;
    }

    conf->remote = addr;
    return 0;
}

// Range: 0x1D0 -> 0x234
static int ReceiveConfigureAck(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    if (lcp->len != conf->len + 4 || memcmp(lcp + 1, conf->data, conf->len) != 0) {
        return FALSE;
    }
    return TRUE;
}

// Range: 0x234 -> 0x35C
static int ReceiveConfigureNak(PPPConf* conf /* r29 */, LCPHeader* lcp /* r24 */) {
    // Local variables
    u8* data; // r27
    u16 len; // r26
    LCPOpt* cur; // r30
    LCPOpt* nak; // r31
    LCPOpt* end; // r28
    u32 addr; // r25

    data = (u8*)lcp + sizeof(LCPHeader);
    len = lcp->len - sizeof(LCPHeader);
    for (nak = (LCPOpt*)data; (u8*)nak < data + len; nak = (LCPOpt*)((u8*)nak + nak->len)) {
        switch (nak->type) {
            case 3:
            case 0x81:
            case 0x83:
                if (nak->len != 6) {
                    return FALSE;
                }
                end = (LCPOpt*)(conf->data + conf->len);
                for (cur = (LCPOpt*)conf->data; cur < end; cur = (LCPOpt*)((u8*)cur + cur->len)) {
                    if (nak->type == cur->type) {
                        switch (cur->type) {
                            case 3:
                            case 0x81:
                            case 0x83:
                                addr = *(u32*)(nak + 1);
                                *(u32*)(cur + 1) = addr;
                                break;
                        }
                        break;
                    }
                }
                if (end <= cur) {
                    memmove(end, nak, nak->len);
                    conf->len = conf->len + nak->len;
                }
                break;
        }
    }
    return TRUE;
}

// Range: 0x35C -> 0x408
static int ReceiveConfigureReject(PPPConf* conf /* r30 */, LCPHeader* lcp /* r25 */) {
    // Local variables
    u8* data; // r28
    u16 len; // r27
    LCPOpt* cur; // r31
    LCPOpt* rej; // r29
    LCPOpt* end; // r26

    data = (u8*)lcp + sizeof(LCPHeader);
    len = lcp->len - sizeof(LCPHeader);
    cur = (LCPOpt*)conf->data;
    for (rej = (LCPOpt*)data; (u8*)rej < data + len; (u8*)rej += rej->len) {
        end = (LCPOpt*)(conf->data + conf->len);
        while (rej->type != cur->type) {
            if (end <= cur) {
                return FALSE;
            }
            (u8*)cur += cur->len;
        }
        conf->len = PPPDeleteOpt(conf->data, conf->len, cur);
    }
    return TRUE;
}

// Range: 0x408 -> 0x514
static int Up(PPPConf* conf /* r30 */) {
    // Local variables
    LCPOpt* opt; // r31
    LCPOpt* end; // r26
    u8* addr; // r29
    u8* dns1; // r28
    u8* dns2; // r27
    u8 prev1[4]; // r1+0x10
    u8 prev2[4]; // r1+0xC

    // References
    // -> const u8 IPAddrAny[4];
    // -> const u8 IPLimited[4];

    addr = NULL;
    dns1 = NULL;
    dns2 = NULL;
    end = (LCPOpt*)(conf->data + conf->len);
    for (opt = (LCPOpt*)conf->data; opt < end; opt = (LCPOpt*)((u8*)opt + opt->len)) {
        switch (opt->type) {
            case 3:
                addr = (u8*)(opt + 1);
                break;
            case 0x81:
                dns1 = (u8*)(opt + 1);
                break;
            case 0x83:
                dns2 = (u8*)(opt + 1);
                break;
        }
    }

    IPInitRoute(addr, IPLimited, conf->remote ? (u8*)&conf->remote : IPLimited);
    if (SOGetResolver((SOInAddr*)prev1, (SOInAddr*)prev2) == 0) {
        if (IPEQ(prev1, IPAddrAny) && IPEQ(prev2, IPAddrAny)) {
            SOSetResolver((SOInAddr*)dns1, (SOInAddr*)dns2);
        } else {
            SOSetResolver((SOInAddr*)prev1, (SOInAddr*)prev2);
        }
    }
    return TRUE;
}

// Range: 0x514 -> 0x544
static int Down() {
    IPInitRoute(NULL, NULL, NULL);
    return TRUE;
}

// Range: 0x544 -> 0x54C
static int Started() {
    return TRUE;
}

// Range: 0x54C -> 0x554
static int Finished() {
    return TRUE;
}

// Range: 0x554 -> 0x69C
void PPPInitIPCP(PPPConf* ipcp /* r31 */, IPInterface* interface /* r1+0xC */) {
    // Local variables
    LCPOpt* opt; // r30

    memset(ipcp, 0, sizeof(PPPConf));
    ipcp->protocol = PPP_IPCP;
    OSCreateAlarm(&ipcp->alarm);
    ipcp->interface = interface;
    ipcp->receiveConfigureRequest = ReceiveConfigureRequest;
    ipcp->receiveConfigureAck = ReceiveConfigureAck;
    ipcp->receiveConfigureNak = ReceiveConfigureNak;
    ipcp->receiveConfigureReject = ReceiveConfigureReject;
    ipcp->up = Up;
    ipcp->down = Down;
    ipcp->started = Started;
    ipcp->finished = Finished;

    opt = (LCPOpt*)(ipcp->data + ipcp->len);
    opt->type = 3;
    opt->len = 6;
    *(u32*)(opt + 1) = 0;
    ipcp->len += 6;

    opt = (LCPOpt*)(ipcp->data + ipcp->len);
    opt->type = 0x81;
    opt->len = 6;
    *(u32*)(opt + 1) = 0;
    ipcp->len += 6;

    opt = (LCPOpt*)(ipcp->data + ipcp->len);
    opt->type = 0x83;
    opt->len = 6;
    *(u32*)(opt + 1) = 0;
    ipcp->len += 6;
}
