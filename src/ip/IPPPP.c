#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

PPPAuth __PPPAuth; // size: 0x303, address: 0x0

// Range: 0x0 -> 0x5C
int PPPLayerUp(PPPConf* conf /* r29 */) {
    // Local variables
    int rc; // r31
    PPPConf* upper; // r30

    rc = conf->up(conf);
    if (rc) {
        upper = (PPPConf*)conf->link.next;
        if (upper != NULL) {
            PPPUp(upper);
        }
    }
    return rc;
}

// Range: 0x5C -> 0xA8
int PPPLayerDown(PPPConf* conf /* r30 */) {
    // Local variables
    PPPConf* upper; // r31

    upper = (PPPConf*)conf->link.next;
    if (upper != NULL) {
        PPPDown(upper);
    }
    return conf->down(conf);
}

// Range: 0xA8 -> 0x104
int PPPLayerStarted(PPPConf* conf /* r29 */) {
    // Local variables
    int rc; // r31
    PPPConf* lower; // r30

    rc = conf->started(conf);
    if (rc) {
        lower = (PPPConf*)conf->link.prev;
        if (lower != NULL) {
            PPPOpen(lower);
        }
    }
    return rc;
}

// Range: 0x104 -> 0x160
int PPPLayerFinished(PPPConf* conf /* r29 */) {
    // Local variables
    int rc; // r31
    PPPConf* lower; // r30

    rc = conf->finished(conf);
    if (rc) {
        lower = (PPPConf*)conf->link.prev;
        if (lower != NULL) {
            PPPClose(lower);
        }
    }
    return rc;
}

// Range: 0x160 -> 0x1BC
void PPPInitializeRestartCount(PPPConf* conf /* r31 */) {
    conf->rxmit = 0;
    conf->configure = 10;
    conf->terminate = 2;
    conf->failure = 5;
    conf->id++;
    OSCancelAlarm(&conf->alarm);
}

// Range: 0x1BC -> 0x20C
void PPPZeroRestartCount(PPPConf* conf /* r31 */) {
    conf->rxmit = 0;
    conf->configure = 0;
    conf->terminate = 0;
    conf->failure = 0;
    OSCancelAlarm(&conf->alarm);
}

// Range: 0x20C -> 0x288
void PPPSetState(PPPConf* conf /* r31 */, int state /* r1+0xC */) {
    conf->state = state;
    if (conf->callback) {
        conf->callback(conf);
    }

    switch (conf->state) {
        case PPP_STATE_INITIAL:
        case PPP_STATE_STARTING:
        case PPP_STATE_CLOSED:
        case PPP_STATE_OPENED:
            OSCancelAlarm(&conf->alarm);
            break;
    }
}

// Range: 0x288 -> 0x290
int PPPGetState(PPPConf* conf /* r3 */) {
    return conf->state;
}

// Range: 0x290 -> 0x3DC
static void LCPOut(PPPConf* conf /* r26 */, u8 code /* r25 */, u8 id /* r1+0xD */, s32 len /* r29 */, void* data /* r1+0x14 */) {
    // Local variables
    IPInterface* interface; // r31
    IFDatagram* datagram; // r30
    u16* proto; // r27
    LCPHeader* lcp; // r28
    BOOL enabled; // r24

    enabled = OSDisableInterrupts();
    interface = conf->interface;
    if (code == 1 || code == 5) {
        OSCancelAlarm(&conf->alarm);
        OSSetAlarm(&conf->alarm, OSSecondsToTicks((OSTime)3), PPPTimeout);
    }

    if (interface->mtu < len + 4) {
        len = interface->mtu - sizeof(LCPHeader);
    }

    datagram = (IFDatagram*)interface->alloc(interface, sizeof(IFDatagram) + sizeof(u16) + sizeof(LCPHeader) + len);
    if (datagram != NULL) {
        IFInitDatagram(datagram, 0x8864, 1);
        proto = (u16*)(datagram + 1);
        *proto = conf->protocol;
        lcp = (LCPHeader*)(proto + 1);
        lcp->code = code;
        lcp->id = id;
        lcp->len = len + sizeof(LCPHeader);
        memmove(lcp + 1, data, len);
        datagram->vec[0].data = proto;
        datagram->vec[0].len = len + sizeof(u16) + sizeof(LCPHeader);
        interface->out(interface, datagram);
    }

    OSRestoreInterrupts(enabled);
}

// Range: 0x3DC -> 0x440
static int SendConfigureRequest(PPPConf* conf /* r31 */) {
    if (0 < conf->configure) {
        conf->configure--;
        LCPOut(conf, 1, conf->id, conf->len, conf->data);
        return TRUE;
    }
    return FALSE;
}

// Range: 0x440 -> 0x490
static void SendConfigureAck(PPPConf* conf /* r30 */, LCPHeader* lcp /* r31 */) {
    conf->failure = 5;
    LCPOut(conf, 2, lcp->id, lcp->len - sizeof(LCPHeader), lcp + 1);
}

// Range: 0x490 -> 0x508
static void SendConfigureNak(PPPConf* conf /* r30 */, LCPHeader* lcp /* r31 */) {
    ASSERTLINE(370, 0 < conf->failure);
    conf->failure--;
    LCPOut(conf, 3, lcp->id, lcp->len - sizeof(LCPHeader), lcp + 1);
}

// Range: 0x508 -> 0x550
static void SendConfigureReject(PPPConf* conf /* r1+0x8 */, LCPHeader* lcp /* r31 */) {
    LCPOut(conf, 4, lcp->id, lcp->len - sizeof(LCPHeader), lcp + 1);
}

// Range: 0x550 -> 0x5B4
static int SendTerminateRequest(PPPConf* conf /* r31 */) {
    if (0 < conf->terminate) {
        conf->terminate--;
        LCPOut(conf, 5, conf->id, 0, NULL);
        return TRUE;
    }
    return FALSE;
}

// Range: 0x5B4 -> 0x5F4
static void SendTerminateAck(PPPConf* conf /* r31 */) {
    LCPOut(conf, 6, conf->idTerminate, 0, NULL);
}

// Range: 0x5F4 -> 0x644
static void SendCodeReject(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    conf->idReject++;
    LCPOut(conf, 7, conf->idReject, lcp->len, lcp);
}

// Range: 0x644 -> 0x694
static void SendProtocolReject(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    conf->idReject++;
    LCPOut(conf, 8, conf->idReject, lcp->len, lcp);
}

// Range: 0x694 -> 0x6DC
static void SendEchoReply(PPPConf* conf /* r30 */, LCPHeader* lcp /* r31 */) {
    LCPOut(conf, 10, conf->idEcho, lcp->len - sizeof(LCPHeader), lcp + 1);
}

// Range: 0x6DC -> 0x9A8
static void ReceiveConfigureRequest(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    // Local variables
    int rc; // r29
    u8* data; // r1+0x10

    data = (u8*)(lcp + 1);
    rc = conf->receiveConfigureRequest(conf, lcp);
    switch (rc) {
        case 0:
            switch (conf->state) {
                case PPP_STATE_CLOSED:
                    SendTerminateAck(conf);
                    break;
                case PPP_STATE_STOPPED:
                    PPPInitializeRestartCount(conf);
                    SendConfigureRequest(conf);
                    SendConfigureAck(conf, lcp);
                    PPPSetState(conf, PPP_STATE_ACK_SENT);
                    break;
                case PPP_STATE_REQ_SENT:
                    SendConfigureAck(conf, lcp);
                    PPPSetState(conf, PPP_STATE_ACK_SENT);
                    break;
                case PPP_STATE_ACK_RCVD:
                    SendConfigureAck(conf, lcp);
                    PPPSetState(conf, PPP_STATE_OPENED);
                    PPPLayerUp(conf);
                    break;
                case PPP_STATE_ACK_SENT:
                    SendConfigureAck(conf, lcp);
                    break;
                case PPP_STATE_OPENED:
                    SendConfigureRequest(conf);
                    SendConfigureAck(conf, lcp);
                    PPPSetState(conf, PPP_STATE_ACK_SENT);
                    PPPLayerDown(conf);
                    break;
            }
            break;
        case -1:
            switch (conf->state) {
                case PPP_STATE_CLOSED:
                    SendTerminateAck(conf);
                    break;
                case PPP_STATE_STOPPED:
                    PPPInitializeRestartCount(conf);
                    SendConfigureRequest(conf);
                    SendConfigureReject(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
                case PPP_STATE_REQ_SENT:
                    SendConfigureReject(conf, lcp);
                    break;
                case PPP_STATE_ACK_RCVD:
                    SendConfigureReject(conf, lcp);
                    break;
                case PPP_STATE_ACK_SENT:
                    SendConfigureReject(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
                case PPP_STATE_OPENED:
                    SendConfigureRequest(conf);
                    SendConfigureReject(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    PPPLayerDown(conf);
                    break;
            }
            break;
        case -2:
            switch (conf->state) {
                case PPP_STATE_CLOSED:
                    SendTerminateAck(conf);
                    break;
                case PPP_STATE_STOPPED:
                    PPPInitializeRestartCount(conf);
                    SendConfigureRequest(conf);
                    SendConfigureNak(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
                case PPP_STATE_REQ_SENT:
                    SendConfigureNak(conf, lcp);
                    break;
                case PPP_STATE_ACK_RCVD:
                    SendConfigureNak(conf, lcp);
                    break;
                case PPP_STATE_ACK_SENT:
                    SendConfigureNak(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
                case PPP_STATE_OPENED:
                    SendConfigureRequest(conf);
                    SendConfigureNak(conf, lcp);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    PPPLayerDown(conf);
                    break;
            }
            break;
        case -3:
            return;
    }
}

// Range: 0x9A8 -> 0xA90
static void ReceiveConfigureAck(PPPConf* conf /* r31 */, LCPHeader* lcp /* r1+0xC */) {
    // Local variables
    int rc; // r30

    rc = conf->receiveConfigureAck(conf, lcp);
    if (rc) {
        switch (conf->state) {
            case PPP_STATE_CLOSED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_STOPPED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_REQ_SENT:
                PPPInitializeRestartCount(conf);
                PPPSetState(conf, PPP_STATE_ACK_RCVD);
                break;
            case PPP_STATE_ACK_RCVD:
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_ACK_SENT:
                PPPInitializeRestartCount(conf);
                PPPSetState(conf, PPP_STATE_OPENED);
                PPPLayerUp(conf);
                break;
            case PPP_STATE_OPENED:
                SendConfigureRequest(conf);
                PPPSetState(conf, PPP_STATE_REQ_SENT);
                PPPLayerDown(conf);
                break;
        }
    }
}

// Range: 0xA90 -> 0xB68
static void ReceiveConfigureNak(PPPConf* conf /* r31 */, LCPHeader* lcp /* r1+0xC */) {
    // Local variables
    int rc; // r30

    rc = conf->receiveConfigureNak(conf, lcp);
    if (rc) {
        switch (conf->state) {
            case PPP_STATE_CLOSED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_STOPPED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_REQ_SENT:
                PPPInitializeRestartCount(conf);
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_ACK_RCVD:
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_ACK_SENT:
                PPPInitializeRestartCount(conf);
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_OPENED:
                SendConfigureRequest(conf);
                PPPSetState(conf, PPP_STATE_REQ_SENT);
                PPPLayerDown(conf);
                break;
        }
    }
}

// Range: 0xB68 -> 0xC40
static void ReceiveConfigureReject(PPPConf* conf /* r31 */, LCPHeader* lcp /* r1+0xC */) {
    // Local variables
    int rc; // r30

    rc = conf->receiveConfigureReject(conf, lcp);
    if (rc) {
        switch (conf->state) {
            case PPP_STATE_CLOSED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_STOPPED:
                SendTerminateAck(conf);
                break;
            case PPP_STATE_REQ_SENT:
                PPPInitializeRestartCount(conf);
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_ACK_RCVD:
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_ACK_SENT:
                PPPInitializeRestartCount(conf);
                SendConfigureRequest(conf);
                break;
            case PPP_STATE_OPENED:
                SendConfigureRequest(conf);
                PPPSetState(conf, PPP_STATE_REQ_SENT);
                PPPLayerDown(conf);
                break;
        }
    }
}

// Range: 0xC40 -> 0xD2C
static void ReceiveTerminateRequest(PPPConf* conf /* r31 */, LCPHeader* lcp /* r1+0xC */) {
    conf->idTerminate = lcp->id;
    switch (conf->state) {
        case PPP_STATE_CLOSED:
            SendTerminateAck(conf);
            break;
        case PPP_STATE_STOPPED:
            SendTerminateAck(conf);
            break;
        case PPP_STATE_CLOSING:
            SendTerminateAck(conf);
            break;
        case PPP_STATE_STOPPING:
            SendTerminateAck(conf);
            break;
        case PPP_STATE_REQ_SENT:
            SendTerminateAck(conf);
            break;
        case PPP_STATE_ACK_RCVD:
            SendTerminateAck(conf);
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            break;
        case PPP_STATE_ACK_SENT:
            SendTerminateAck(conf);
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            break;
        case PPP_STATE_OPENED:
            PPPZeroRestartCount(conf);
            SendTerminateAck(conf);
            PPPSetState(conf, PPP_STATE_STOPPING);
            PPPLayerDown(conf);
            break;
    }
}

// Range: 0xD2C -> 0xDE4
static void ReceiveTerminateAck(PPPConf* conf /* r31 */, LCPHeader* lcp) {
    switch (conf->state) {
        case PPP_STATE_CLOSING:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_STOPPING:
            PPPSetState(conf, PPP_STATE_STOPPED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_ACK_RCVD:
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            break;
        case PPP_STATE_OPENED:
            SendConfigureRequest(conf);
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            PPPLayerDown(conf);
            break;
        case PPP_STATE_REQ_SENT:
            (void)0;
            break;
    }
}

// Range: 0xDE4 -> 0xEB0
static void ReceiveUnknownCode(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    switch (conf->state) {
        case PPP_STATE_CLOSED:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_STOPPED:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_CLOSING:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_STOPPING:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_REQ_SENT:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_ACK_RCVD:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_ACK_SENT:
            SendCodeReject(conf, lcp);
            break;
        case PPP_STATE_OPENED:
            SendCodeReject(conf, lcp);
            break;
    }
}

// Range: 0xEB0 -> 0xFD4
static void ReceiveCodeReject(PPPConf* conf /* r31 */, LCPHeader* lcp) {
    // Local variables
    int plus; // r30

    plus = FALSE;
    if (plus) {
        switch (conf->state) {
            case PPP_STATE_ACK_RCVD:
                PPPSetState(conf, PPP_STATE_REQ_SENT);
                break;
        }
    } else {
        switch (conf->state) {
            case PPP_STATE_CLOSED:
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_STOPPED:
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_CLOSING:
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_STOPPING:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_REQ_SENT:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_ACK_RCVD:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_ACK_SENT:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_OPENED:
                PPPInitializeRestartCount(conf);
                PPPSetState(conf, PPP_STATE_STOPPING);
                PPPLayerDown(conf);
                break;
        }
    }
}

// Range: 0xFD4 -> 0x10F8
static void ReceiveProtocolReject(PPPConf* conf /* r31 */, LCPHeader* lcp) {
    // Local variables
    int plus; // r30

    plus = FALSE;
    if (plus) {
        switch (conf->state) {
            case PPP_STATE_ACK_RCVD:
                PPPSetState(conf, PPP_STATE_REQ_SENT);
                break;
        }
    } else {
        switch (conf->state) {
            case PPP_STATE_CLOSED:
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_STOPPED:
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_CLOSING:
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_STOPPING:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_REQ_SENT:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_ACK_RCVD:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_ACK_SENT:
                PPPSetState(conf, PPP_STATE_STOPPED);
                PPPLayerFinished(conf);
                break;
            case PPP_STATE_OPENED:
                PPPInitializeRestartCount(conf);
                PPPSetState(conf, PPP_STATE_STOPPING);
                PPPLayerDown(conf);
                break;
        }
    }
}

// Range: 0x10F8 -> 0x1148
static void ReceiveEchoRequest(PPPConf* conf /* r31 */, LCPHeader* lcp /* r30 */) {
    conf->idEcho = lcp->id;
    switch (conf->state) {
        case PPP_STATE_OPENED:
            SendEchoReply(conf, lcp);
            break;
    }
}

// Range: 0x1148 -> 0x12A4
static void LCPIn(PPPConf* conf /* r30 */, LCPHeader* lcp /* r31 */, s32 len /* r29 */, u32 flag) {
    if (conf == NULL || len < 4 || len < lcp->len || lcp->len < sizeof(LCPHeader)) {
        return;
    }

    switch (lcp->code) {
        case 1:
            ReceiveConfigureRequest(conf, lcp);
            break;
        case 2:
            if (lcp->id == conf->id) {
                ReceiveConfigureAck(conf, lcp);
            }
            break;
        case 3:
            if (lcp->id == conf->id) {
                ReceiveConfigureNak(conf, lcp);
            }
            break;
        case 4:
            if (lcp->id == conf->id) {
                ReceiveConfigureReject(conf, lcp);
            }
            break;
        case 5:
            ReceiveTerminateRequest(conf, lcp);
            break;
        case 6:
            if (lcp->id == conf->id) {
                ReceiveTerminateAck(conf, lcp);
            }
            break;
        case 7:
            ReceiveCodeReject(conf, lcp);
            break;
        case 8:
            ReceiveProtocolReject(conf, lcp);
            break;
        case 9:
            ReceiveEchoRequest(conf, lcp);
            break;
        case 10:
        case 11:
            break;
        default:
            ReceiveUnknownCode(conf, lcp);
            break;
    }
}

// Range: 0x12A4 -> 0x149C
void PPPIn(IPInterface* interface /* r25 */, u8* ppp /* r30 */, s32 len /* r29 */, u32 flag /* r28 */) {
    // Local variables
    u16 protocol; // r27
    PPPConf* conf; // r31
    PPPConf* next; // r24
    PPPConf* lcp; // r26
    PPPConf* ipcp; // r23

    if (len < 2) {
        return;
    }

    len -= sizeof(u16);
    protocol = *(u16*)ppp;
    ppp += sizeof(u16);

    if (protocol == PPP_IP) {
        ipcp = (PPPConf*)interface->ppp.prev;
        ASSERTLINE(1001, ipcp->protocol == PPP_IPCP);
        if (ipcp->state == PPP_STATE_OPENED) {
            IPIn(interface, (IPHeader*)ppp, len, flag);
        }
        return;
    }

    IFQueueIterator(PPPConf*, &interface->ppp, conf, next) {
        if (protocol == conf->protocol) {
            break;
        }
    }

    if (conf == NULL) {
        lcp = (PPPConf*)interface->ppp.next;
        ASSERTLINE(1022, lcp->protocol == PPP_LCP);
        if (lcp->state == PPP_STATE_OPENED) {
            SendProtocolReject(lcp, (LCPHeader*)ppp);
        }
        return;
    }

    switch (protocol) {
        case PPP_LCP:
            LCPIn(conf, (LCPHeader*)ppp, len, flag);
            break;
        case PPP_IPCP:
            LCPIn(conf, (LCPHeader*)ppp, len, flag);
            break;
        case PPP_PAP:
            PAPIn(conf, (PAPHeader*)ppp, len, flag);
            break;
        case PPP_CHAP:
            CHAPIn(conf, (CHAPHeader*)ppp, len, flag);
            break;
    }
}

// Range: 0x149C -> 0x1598
void PPPOpen(PPPConf* conf /* r31 */) {
    // Local variables
    BOOL enabled; // r30

    enabled = OSDisableInterrupts();
    switch (conf->protocol) {
        case PPP_PAP:
            PAPOpen(conf);
            break;
        case PPP_CHAP:
            CHAPOpen(conf);
            break;
        default:
            switch (conf->state) {
                case PPP_STATE_INITIAL:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    PPPLayerStarted(conf);
                    break;
                case PPP_STATE_STARTING:
                    break;
                case PPP_STATE_CLOSED:
                    PPPInitializeRestartCount(conf);
                    SendConfigureRequest(conf);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
                case PPP_STATE_STOPPED:
                    break;
                case PPP_STATE_CLOSING:
                    PPPSetState(conf, PPP_STATE_STOPPING);
                    break;
                case PPP_STATE_STOPPING:
                case PPP_STATE_REQ_SENT:
                case PPP_STATE_ACK_RCVD:
                case PPP_STATE_ACK_SENT:
                case PPP_STATE_OPENED:
                    break;
            }
            break;
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x1598 -> 0x165C
void PPPUp(PPPConf* conf /* r31 */) {
    // Local variables
    BOOL enabled; // r30

    enabled = OSDisableInterrupts();
    switch (conf->protocol) {
        case PPP_PAP:
            PAPUp(conf);
            break;
        case PPP_CHAP:
            CHAPUp(conf);
            break;
        default:
            switch (conf->state) {
                case PPP_STATE_INITIAL:
                    PPPSetState(conf, PPP_STATE_CLOSED);
                    break;
                case PPP_STATE_STARTING:
                    PPPInitializeRestartCount(conf);
                    SendConfigureRequest(conf);
                    PPPSetState(conf, PPP_STATE_REQ_SENT);
                    break;
            }
            break;
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x165C -> 0x1788
void PPPDown(PPPConf* conf /* r31 */) {
    // Local variables
    BOOL enabled; // r30

    enabled = OSDisableInterrupts();
    switch (conf->protocol) {
        case PPP_PAP:
            PAPDown(conf);
            break;
        case PPP_CHAP:
            CHAPDown(conf);
            break;
        default:
            switch (conf->state) {
                case PPP_STATE_CLOSED:
                    PPPSetState(conf, PPP_STATE_INITIAL);
                    break;
                case PPP_STATE_STOPPED:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    PPPLayerStarted(conf);
                    break;
                case PPP_STATE_CLOSING:
                    PPPSetState(conf, PPP_STATE_INITIAL);
                    break;
                case PPP_STATE_STOPPING:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    break;
                case PPP_STATE_REQ_SENT:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    break;
                case PPP_STATE_ACK_RCVD:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    break;
                case PPP_STATE_ACK_SENT:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    break;
                case PPP_STATE_OPENED:
                    PPPSetState(conf, PPP_STATE_STARTING);
                    PPPLayerDown(conf);
                    break;
            }
            break;
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x1788 -> 0x18E4
void PPPClose(PPPConf* conf /* r31 */) {
    // Local variables
    BOOL enabled; // r30

    enabled = OSDisableInterrupts();
    switch (conf->protocol) {
        case PPP_PAP:
            PAPClose(conf);
            break;
        case PPP_CHAP:
            CHAPClose(conf);
            break;
        default:
            switch (conf->state) {
                case PPP_STATE_STARTING:
                    PPPSetState(conf, PPP_STATE_INITIAL);
                    PPPLayerFinished(conf);
                    break;
                case PPP_STATE_STOPPED:
                    PPPSetState(conf, PPP_STATE_CLOSED);
                    break;
                case PPP_STATE_STOPPING:
                    PPPSetState(conf, PPP_STATE_CLOSING);
                    break;
                case PPP_STATE_REQ_SENT:
                    PPPInitializeRestartCount(conf);
                    SendTerminateRequest(conf);
                    PPPSetState(conf, PPP_STATE_CLOSING);
                    break;
                case PPP_STATE_ACK_RCVD:
                    PPPInitializeRestartCount(conf);
                    SendTerminateRequest(conf);
                    PPPSetState(conf, PPP_STATE_CLOSING);
                    break;
                case PPP_STATE_ACK_SENT:
                    PPPInitializeRestartCount(conf);
                    SendTerminateRequest(conf);
                    PPPSetState(conf, PPP_STATE_CLOSING);
                    break;
                case PPP_STATE_OPENED:
                    PPPInitializeRestartCount(conf);
                    SendTerminateRequest(conf);
                    PPPSetState(conf, PPP_STATE_CLOSING);
                    PPPLayerDown(conf);
                    break;
            }
            break;
    }
    OSRestoreInterrupts(enabled);
}

// Range: 0x18E4 -> 0x1AB4
void PPPTimeout(OSAlarm* alarm /* r1+0x8 */, OSContext* context) {
    // Local variables
    PPPConf* conf; // r31
    int expired; // r30

    conf = (PPPConf*)((u8*)alarm - offsetof(PPPConf, alarm));
    conf->rxmit++;
    switch (conf->protocol) {
        case PPP_PAP:
            expired = !PAPTimeout(conf);
            break;
        case PPP_CHAP:
            expired = !CHAPTimeout(conf);
            break;
        default:
            switch (conf->state) {
                case PPP_STATE_CLOSING:
                    expired = !SendTerminateRequest(conf);
                    if (expired) {
                        PPPSetState(conf, PPP_STATE_CLOSED);
                        PPPLayerFinished(conf);
                    }
                    break;
                case PPP_STATE_STOPPING:
                    expired = !SendTerminateRequest(conf);
                    if (expired) {
                        PPPSetState(conf, PPP_STATE_STOPPED);
                        PPPLayerFinished(conf);
                    }
                    break;
                case PPP_STATE_REQ_SENT:
                    expired = !SendConfigureRequest(conf);
                    if (expired) {
                        PPPSetState(conf, PPP_STATE_STOPPED);
                        PPPLayerFinished(conf);
                    }
                    break;
                case PPP_STATE_ACK_RCVD:
                    expired = !SendConfigureRequest(conf);
                    if (expired) {
                        PPPSetState(conf, PPP_STATE_STOPPED);
                        PPPLayerFinished(conf);
                    } else {
                        PPPSetState(conf, PPP_STATE_REQ_SENT);
                    }
                    break;
                case PPP_STATE_ACK_SENT:
                    expired = !SendConfigureRequest(conf);
                    if (expired) {
                        PPPSetState(conf, PPP_STATE_STOPPED);
                        PPPLayerFinished(conf);
                    }
                    break;
            }
            break;
    }

    if (expired) {
        IPSetConfigError(conf->interface, -103);
    }
}

// Range: 0x1AB4 -> 0x1B10
u16 PPPDeleteOpt(u8* data /* r1+0x8 */, u16 len /* r28 */, LCPOpt* opt /* r29 */) {
    // Local variables
    u16 optlen; // r31
    u8* next; // r30

    optlen = opt->len;
    next = (u8*)opt + optlen;
    memmove(opt, next, data + len - next);
    return len - optlen;
}

// Range: 0x1B10 -> 0x1B80
u16 PPPInsertOpt(u8* data /* r1+0x8 */, u16 len /* r28 */, LCPOpt* at /* r30 */, LCPOpt* opt /* r31 */) {
    // Local variables
    u8* to; // r29

    to = (u8*)at + opt->len;
    memmove(to, at, data + len - (u8*)at);
    memmove(at, opt, opt->len);
    return len + opt->len;
}

// Range: 0x1B80 -> 0x1CD8
int PPPInit(IPInterface* interface /* r31 */, PPPConf* lcp /* r25 */, PPPConf* ipcp /* r27 */, const char* peerid /* r23 */, const char* password /* r24 */) {
    // Local variables
    unsigned int len; // r26

    // References
    // -> PPPAuth __PPPAuth;

    PPPInitLCP(lcp, interface);
    PPPInitIPCP(ipcp, interface);
    IFQueueInit(&interface->ppp);
    IFQueueEnqueueTail(PPPConf*, &interface->ppp, lcp);
    IFQueueEnqueueTail(PPPConf*, &interface->ppp, ipcp);

    if (peerid != NULL) {
        len = strlen(peerid);
        if (len > 255) {
            IPSetConfigError(NULL, -108);
            return FALSE;
        }
        __PPPAuth.peerIdLen = len;
        strncpy(__PPPAuth.peerId, peerid, 256);
    }

    if (password != NULL) {
        len = strlen(password);
        if (len > 255) {
            IPSetConfigError(NULL, -108);
            return FALSE;
        }
        __PPPAuth.passwordLen = len;
        strncpy(__PPPAuth.password, password, 256);
    }

    __PPPAuth.messageLen = 0;
    __PPPAuth.message[0] = '\0';
    PPPOpen(ipcp);
    return TRUE;
}

// Range: 0x1CD8 -> 0x1CE8
char* PPPGetMessage(void) {
    // References
    // -> PPPAuth __PPPAuth;

    return __PPPAuth.message;
}
