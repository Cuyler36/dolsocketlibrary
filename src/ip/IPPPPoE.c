#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static void TimeoutCallback(OSAlarm* alarm, OSContext*);
static void Out(IPInterface* interface, IFDatagram* datagram);

static PPPoEConf Conf = { 0, 0xFFFF, 0xFFFF }; // size: 0x628, address: 0x0

// Range: 0x0 -> 0x1C8
static void DumpTags(PPPoEHeader* pppoe /* r29 */) {
    // Local variables
    PPPoETag* tag; // r31

    for (tag = (PPPoETag*)(pppoe + 1); (u8*)tag < (u8*)pppoe + pppoe->len && tag->type != PPPoE_TAG_END_OF_LIST;
         tag = (PPPoETag*)((u8*)tag + (tag->len + sizeof(PPPoETag)))) {
        switch (tag->type) {
            case PPPoE_TAG_END_OF_LIST:
                OSReport(" EndOfList(%x)", tag->type);
                break;
            case PPPoE_TAG_SERVICE_NAME:
                OSReport(" ServiceName(%x)", tag->type);
                break;
            case PPPoE_TAG_AC_NAME:
                OSReport(" ACName(%x:%*.*s)", tag->type, tag->len, tag->len, tag + 1);
                break;
            case PPPoE_TAG_HOST_UNIQ:
                OSReport(" HostUniq(%x)", tag->type);
                break;
            case PPPoE_TAG_AC_COOKIE:
                OSReport(" ACCookie(%x)", tag->type);
                break;
            case PPPoE_TAG_VENDOR_SPECIFIC:
                OSReport(" VendorSpecific(%x)", tag->type);
                break;
            case PPPoE_TAG_RELAY_SESSION_ID:
                OSReport(" RelaySessionId(%x)", tag->type);
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                OSReport(" ServiceNameError(%x:%*.*s)", tag->type, tag->len, tag->len, tag + 1);
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                OSReport(" ACSystemError(%x:%*.*s)", tag->type, tag->len, tag->len, tag + 1);
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                OSReport(" GenericError(%x:%*.*s)", tag->type, tag->len, tag->len, tag + 1);
                break;
            default:
                OSReport(" Unknown(%x)", tag->type);
                break;
        }
    }
}

// Range: 0x1C8 -> 0x33C
void PPPoEDumpPacket(PPPoEHeader* pppoe /* r31 */) {
    // Local variables
    u16 proto; // r29

    OSReport("pppoe: ver=%d type=%d code=%04x session=%d len=%d: ", (pppoe->vertype & 0xF0) >> 4, pppoe->vertype & 0xF, pppoe->code,
             pppoe->session, pppoe->len);
    switch (pppoe->code) {
        case PPPoE_SESSION:
            proto = *(u16*)(pppoe + 1);
            switch (proto) {
                case PPP_LCP:
                    PPPDumpLCP((LCPHeader*)((u8*)(pppoe + 1) + sizeof(u16)));
                    break;
                default:
                    OSReport("SESS: proto=%x", proto);
                    break;
            }
            break;
        case PPPoE_PADI:
            OSReport("PADI: ");
            DumpTags(pppoe);
            break;
        case PPPoE_PADO:
            OSReport("PADO: ");
            DumpTags(pppoe);
            break;
        case PPPoE_PADR:
            OSReport("PADR: ");
            DumpTags(pppoe);
            break;
        case PPPoE_PADS:
            OSReport("PADS: ");
            DumpTags(pppoe);
            break;
        case PPPoE_PADT:
            OSReport("PADT: ");
            DumpTags(pppoe);
            break;
        default:
            OSReport("Unknown(%x): ", pppoe->code);
            break;
    }
    OSReport("\n");
}

// Range: 0x33C -> 0x40C
static void OutPADT(IPInterface* interface /* r29 */, u8* mac /* r1+0xC */, u16 session /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r28
    IFDatagram* datagram; // r31
    PPPoEHeader* pppoe; // r30
    PPPoEConf* conf; // r27

    // References
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    enabled = OSDisableInterrupts();
    datagram = interface->alloc(interface, sizeof(IFDatagram) + sizeof(PPPoEHeader));
    pppoe = (PPPoEHeader*)(datagram + 1);
    if (datagram) {
        IFInitDatagram(datagram, ETH_PPPoE_DISCOVERY, 1);
        pppoe->vertype = 0x11;
        pppoe->code = PPPoE_PADT;
        pppoe->session = session;
        pppoe->len = 0;
        datagram->vec[0].data = pppoe;
        datagram->vec[0].len = sizeof(PPPoEHeader);
        memmove(datagram->hwAddr, mac, 6);
        conf->out(interface, datagram);
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x40C -> 0x53C
static void PPPoEOut(IPInterface* interface /* r28 */, PPPoEConf* conf /* r31 */) {
    // Local variables
    BOOL enabled; // r27
    IFDatagram* datagram; // r30
    PPPoEHeader* pppoe; // r29

    enabled = OSDisableInterrupts();
    OSCancelAlarm(&conf->alarm);
    OSSetAlarm(&conf->alarm, OSSecondsToTicks((OSTime)(3 << conf->rxmit)), TimeoutCallback);
    if (conf->code == PPPoE_PADT) {
        OutPADT(interface, conf->mac, conf->session);
    } else {
        datagram = interface->alloc(interface, sizeof(IFDatagram));
        pppoe = (PPPoEHeader*)conf->pppoe;
        pppoe->code = conf->code;
        pppoe->session = conf->session;
        pppoe->len = conf->len;
        if (datagram) {
            IFInitDatagram(datagram, ETH_PPPoE_DISCOVERY, 1);
            datagram->vec[0].data = pppoe;
            datagram->vec[0].len = conf->len + sizeof(PPPoEHeader);
            memmove(datagram->hwAddr, conf->mac, 6);
            conf->out(interface, datagram);
        }
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x53C -> 0x5C8
static void PPPoEQuit(PPPoEConf* conf /* r31 */, u16 last /* r29 */) {
    // Local variables
    PPPConf* lcp; // r30

    OSCancelAlarm(&conf->alarm);
    conf->code = 0;
    conf->session = 0xFFFF;
    conf->last = last;
    if (last != 0xFFFF) {
        memmove(conf->lastmac, conf->mac, 6);
    }
    conf->interface->mtu = 1500;
    lcp = (PPPConf*)conf->interface->ppp.next;
    if (lcp) {
        PPPDown(lcp);
    }
}

// Range: 0x5C8 -> 0x65C
static void TimeoutCallback(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    PPPoEConf* conf; // r31

    conf = (PPPoEConf*)((u8*)alarm - offsetof(PPPoEConf, alarm));
    conf->rxmit++;
    if (conf->code == PPPoE_PADT) {
        PPPoEQuit(conf, 0xFFFF);
    } else if (conf->rxmit >= 4) {
        IPSetConfigError(conf->interface, -0x67);
        PPPoEQuit(conf, 0xFFFF);
    } else {
        PPPoEOut(conf->interface, conf);
    }
}

// Range: 0x65C -> 0x7B0
static void Out(IPInterface* interface /* r25 */, IFDatagram* datagram /* r31 */) {
    // Local variables
    BOOL enabled; // r27
    PPPoEConf* conf; // r29
    PPPoEHeader* pppoe; // r30
    IFVec* vec; // r28
    IFVec* end; // r26

    // References
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    enabled = OSDisableInterrupts();
    if (datagram->type != ETH_IP || !IPIsLoopbackAddr(interface, datagram->dst)) {
        pppoe = (PPPoEHeader*)datagram->prefix;
        pppoe->vertype = 0x11;
        pppoe->code = conf->code;
        pppoe->session = conf->session;
        pppoe->len = 0;
        for (vec = datagram->vec, end = &datagram->vec[datagram->nVec]; vec < end; vec++) {
            pppoe->len += (u16)vec->len;
        }
        switch (datagram->type) {
            case ETH_IP:
                *(u16*)&datagram->prefix[sizeof(PPPoEHeader)] = 0x0021;
                pppoe->len += 2;
                datagram->prefixLen = 8;
                datagram->type = ETH_PPPoE_SESSION;
                break;
            case ETH_PPPoE_SESSION:
                datagram->prefixLen = 6;
                break;
            default:
                datagram->prefixLen = 0;
                break;
        }
        if (datagram->type == ETH_PPPoE_SESSION) {
            memmove(datagram->hwAddr, conf->mac, 6);
        }
    }
    conf->out(interface, datagram);
    OSRestoreInterrupts(enabled);
}

// Range: 0x7B0 -> 0x7B8
void PPPoEInit(IPInterface* interface /* r3 */, const char* serviceName /* r4 */) {
    interface->serviceName = serviceName;
}

// Range: 0x7B8 -> 0x8F8
BOOL PPPoEOpen(IPInterface* interface /* r30 */) {
    // Local variables
    PPPoEHeader* pppoe; // r28
    PPPoETag* tag; // r27
    PPPoEConf* conf; // r31
    u32 len; // r29

    // References
    // -> struct PPPConf PPPLcpConf;
    // -> struct IPInterface __IFDefault;
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    if (conf->session != 0xFFFF) {
        return FALSE;
    }
    interface = interface ? interface : &__IFDefault;
    PPPLcpConf.mru = 1492;
    if (interface->serviceName) {
        len = strlen(interface->serviceName);
        if (len > 1474) {
            len = 0;
        }
    } else {
        len = 0;
    }
    conf->code = PPPoE_PADI;
    conf->len = len + sizeof(PPPoETag);
    conf->session = 0;
    memset(conf->mac, 0xFF, 6);
    OSCreateAlarm(&conf->alarm);
    conf->rxmit = 0;

    pppoe = (PPPoEHeader*)conf->pppoe;
    pppoe->vertype = 0x11;
    pppoe->code = conf->code;
    pppoe->session = conf->session;
    pppoe->len = conf->len;
    tag = (PPPoETag*)(pppoe + 1);
    tag->type = PPPoE_TAG_SERVICE_NAME;
    tag->len = len;
    if (len) {
        memmove(tag + 1, interface->serviceName, len);
    }

    conf->interface = interface;
    conf->out = interface->out;
    interface->out = Out;
    PPPoEOut(interface, conf);
    return TRUE;
}

// Range: 0x8F8 -> 0x998
void PPPoETerminate(IPInterface* interface /* r30 */) {
    // Local variables
    PPPoEConf* conf; // r31
    PPPConf* lcp; // r29

    // References
    // -> struct IPInterface __IFDefault;
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    interface = interface ? interface : &__IFDefault;
    lcp = (PPPConf*)interface->ppp.next;
    if (lcp && conf->session != 0xFFFF && conf->code == 0) {
        conf->code = PPPoE_PADT;
        conf->rxmit = 0;
        PPPoEOut(interface, conf);
    }
    if (interface->out == Out) {
        interface->out = conf->out;
    }
}

// Range: 0x998 -> 0xB10
static s32 ParseTags(PPPoEConf* conf /* r28 */, PPPoEHeader* pppoe /* r25 */) {
    // Local variables
    int result; // r30
    PPPoETag* tag; // r31
    BOOL cookie; // r27
    BOOL acname; // r26
    u16 confLen; // r29

    result = 0;
    acname = cookie = FALSE;
    confLen = conf->len;
    for (tag = (PPPoETag*)(pppoe + 1); (u8*)tag < (u8*)pppoe + pppoe->len && tag->type != PPPoE_TAG_END_OF_LIST;
         tag = (PPPoETag*)((u8*)tag + (tag->len + sizeof(PPPoETag)))) {
        switch (tag->type) {
            case PPPoE_TAG_END_OF_LIST:
            case PPPoE_TAG_SERVICE_NAME:
            case PPPoE_TAG_HOST_UNIQ:
            case PPPoE_TAG_VENDOR_SPECIFIC:
            case PPPoE_TAG_RELAY_SESSION_ID:
                break;
            case PPPoE_TAG_AC_NAME:
                if (!acname && conf->code == PPPoE_PADI) {
                    acname = TRUE;
                    memmove(conf->pppoe + sizeof(PPPoEHeader) + confLen, tag, tag->len + sizeof(PPPoETag));
                    confLen += tag->len + sizeof(PPPoETag);
                }
                break;
            case PPPoE_TAG_AC_COOKIE:
                if (!cookie && conf->code == PPPoE_PADI) {
                    cookie = TRUE;
                    memmove(conf->pppoe + sizeof(PPPoEHeader) + confLen, tag, tag->len + sizeof(PPPoETag));
                    confLen += tag->len + sizeof(PPPoETag);
                }
                break;
            case PPPoE_TAG_SERVICE_NAME_ERROR:
                result = -0x68;
                break;
            case PPPoE_TAG_AC_SYSTEM_ERROR:
                result = -0x69;
                break;
            case PPPoE_TAG_GENERIC_ERROR:
                result = -0x6A;
                break;
        }
    }
    if (result == 0) {
        conf->len = confLen;
    }
    return result;
}

// Range: 0xB10 -> 0xE38
void PPPoEIn(IPInterface* interface /* r26 */, ETHHeader* eh /* r29 */, s32 len /* r24 */, u32 flag /* r1+0x14 */) {
    // Local variables
    PPPoEConf* conf; // r31
    PPPoEHeader* pppoe; // r30
    s32 result; // r28
    PPPConf* lcp; // r27

    // References
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    pppoe = (PPPoEHeader*)(eh + 1);
    if (len < 20 || len < pppoe->len + 20) {
        return;
    }
    if (pppoe->vertype != 0x11) {
        return;
    }
    lcp = (PPPConf*)interface->ppp.next;
    if (lcp == NULL) {
        return;
    }
    ASSERTLINE(603, lcp->protocol == PPP_LCP);

    switch (eh->type) {
        case ETH_PPPoE_DISCOVERY:
            switch (pppoe->code) {
                case PPPoE_PADO:
                    if (conf->code == PPPoE_PADI && pppoe->session == 0) {
                        result = ParseTags(conf, pppoe);
                        if (result == 0) {
                            conf->code = PPPoE_PADR;
                            conf->rxmit = 0;
                            memmove(conf->mac, eh->src, 6);
                            PPPoEOut(interface, conf);
                        } else {
                            IPSetConfigError(conf->interface, result);
                            PPPoEQuit(conf, 0xFFFF);
                        }
                    }
                    break;
                case PPPoE_PADS:
                    if (conf->code == PPPoE_PADR && memcmp(conf->mac, eh->src, 6) == 0) {
                        result = ParseTags(conf, pppoe);
                        if (result == 0 && pppoe->session != 0xFFFF) {
                            conf->code = 0;
                            conf->rxmit = 0;
                            conf->session = pppoe->session;
                            OSCancelAlarm(&conf->alarm);
                            PPPUp(lcp);
                        } else {
                            IPSetConfigError(conf->interface, result);
                            PPPoEQuit(conf, 0xFFFF);
                        }
                    }
                    break;
                case PPPoE_PADT:
                    if (pppoe->session == 0xFFFF) {
                        break;
                    }
                    if (pppoe->session == conf->session && memcmp(conf->mac, eh->src, 6) == 0) {
                        if (conf->code == PPPoE_PADT) {
                            PPPoEQuit(conf, 0xFFFF);
                            break;
                        }
                        if (conf->code == 0) {
                            PPPDown(lcp);
                            PPPoETerminate(interface);
                            IPSetConfigError(conf->interface, -0x6E);
                            PPPoEQuit(conf, conf->session);
                            break;
                        }
                    }
                    if (pppoe->session == conf->last && memcmp(conf->lastmac, eh->src, 6) == 0) {
                        OutPADT(interface, eh->src, pppoe->session);
                    }
                    break;
            }
            break;
        case ETH_PPPoE_SESSION:
            if (pppoe->session != 0xFFFF && conf->code == 0 && pppoe->code == 0 && memcmp(conf->mac, eh->src, 6) == 0 &&
                pppoe->session == conf->session) {
                PPPIn(interface, (u8*)(pppoe + 1), pppoe->len, flag);
            }
            break;
    }
}

// Range: 0xE38 -> 0xF04
int PPPoEGetACName(IPInterface*, char* acname /* r28 */) {
    // Local variables
    BOOL enabled; // r27
    PPPoEConf* conf; // r30
    PPPoETag* tag; // r31
    int rc; // r29

    // References
    // -> static struct PPPoEConf Conf;
    conf = &Conf;
    *acname = '\0';
    enabled = OSDisableInterrupts();
    if (conf->session == 0xFFFF) {
        rc = -1;
    } else {
        rc = 0;
        for (tag = (PPPoETag*)(conf->pppoe + sizeof(PPPoEHeader)); (u8*)tag < conf->pppoe + conf->len && tag->type != PPPoE_TAG_END_OF_LIST;
             tag = (PPPoETag*)((u8*)tag + (tag->len + sizeof(PPPoETag)))) {
            switch (tag->type) {
                case PPPoE_TAG_AC_NAME:
                    memmove(acname, tag + 1, tag->len);
                    acname[tag->len] = '\0';
                    rc = tag->len;
                    goto exit;
            }
        }
    }
exit:
    OSRestoreInterrupts(enabled);
    return rc;
}

PPPConf PPPLcpConf; // size: 0xA0, address: 0x0
PPPConf PPPAuthConf; // size: 0xA0, address: 0xA0
PPPConf PPPIpcpConf; // size: 0xA0, address: 0x140
