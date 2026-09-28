#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

// Range: 0x0 -> 0x194
static void PAPOut(PPPConf* conf /* r26 */) {
    // Local variables
    IPInterface* interface; // r29
    BOOL enabled; // r25
    PAPHeader* pap; // r28
    IFDatagram* datagram; // r31
    s32 len; // r27
    u8* data; // r30

    // References
    // -> PPPAuth __PPPAuth;

    enabled = OSDisableInterrupts();
    interface = conf->interface;
    len = sizeof(u8) + __PPPAuth.peerIdLen + sizeof(u8) + __PPPAuth.passwordLen;
    OSCancelAlarm(&conf->alarm);
    OSSetAlarm(&conf->alarm, OSSecondsToTicks((OSTime)3), PPPTimeout);

    datagram = (IFDatagram*)interface->alloc(interface, sizeof(IFDatagram) + sizeof(u16) + sizeof(PAPHeader) + len);
    if (datagram != NULL) {
        IFInitDatagram(datagram, 0x8864, 1);
        *(u16*)((u8*)datagram + sizeof(IFDatagram)) = PPP_PAP;
        pap = (PAPHeader*)((u8*)datagram + sizeof(IFDatagram) + sizeof(u16));
        pap->code = 1;
        pap->id = conf->id;
        pap->len = len + 4;
        data = (u8*)datagram + sizeof(IFDatagram) + sizeof(u16) + sizeof(PAPHeader);
        *data++ = __PPPAuth.peerIdLen;
        memmove(data, __PPPAuth.peerId, __PPPAuth.peerIdLen);
        data += __PPPAuth.peerIdLen;
        *data++ = __PPPAuth.passwordLen;
        memmove(data, __PPPAuth.password, __PPPAuth.passwordLen);
        datagram->vec[0].data = (u8*)datagram + sizeof(IFDatagram);
        datagram->vec[0].len = len + 6;
        interface->out(interface, datagram);
    }

    OSRestoreInterrupts(enabled);
}

// Range: 0x194 -> 0x1E8
static int SendAuthenticateRequest(PPPConf* conf /* r31 */) {
    if (0 < conf->configure) {
        conf->configure--;
        PAPOut(conf);
        return TRUE;
    }
    return FALSE;
}

// Range: 0x1E8 -> 0x1F0
static int ReceiveAuthenticateRequest() {
    return TRUE;
}

// Range: 0x1F0 -> 0x274
static void GetAuthenticateMessage(PAPHeader* pap /* r1+0x8 */) {
    // Local variables
    char* msg; // r31

    // References
    // -> PPPAuth __PPPAuth;

    msg = (char*)(pap + 1);
    __PPPAuth.messageLen = *msg;
    msg++;
    memcpy(__PPPAuth.message, msg, __PPPAuth.messageLen);
    __PPPAuth.message[__PPPAuth.messageLen] = '\0';
}

// Range: 0x274 -> 0x2C8
static int ReceiveAuthenticateAck(PPPConf* conf /* r31 */, PAPHeader* pap /* r1+0xC */) {
    GetAuthenticateMessage(pap);
    PPPInitializeRestartCount(conf);
    PPPSetState(conf, PPP_STATE_OPENED);
    PPPLayerUp(conf);
    return TRUE;
}

// Range: 0x2C8 -> 0x320
static int ReceiveAuthenticateNak(PPPConf* conf /* r31 */, PAPHeader* pap /* r1+0xC */) {
    GetAuthenticateMessage(pap);
    IPSetConfigError(NULL, -108);
    PPPSetState(conf, PPP_STATE_CLOSED);
    PPPLayerFinished(conf);
    return TRUE;
}

// Range: 0x320 -> 0x3A4
void PAPOpen(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_INITIAL:
            PPPSetState(conf, PPP_STATE_STARTING);
            PPPLayerStarted(conf);
            break;
        case PPP_STATE_STARTING:
            break;
        case PPP_STATE_CLOSED:
            PPPInitializeRestartCount(conf);
            SendAuthenticateRequest(conf);
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            break;
        case PPP_STATE_STOPPED:
        case PPP_STATE_CLOSING:
        case PPP_STATE_STOPPING:
        case PPP_STATE_REQ_SENT:
        case PPP_STATE_ACK_RCVD:
        case PPP_STATE_ACK_SENT:
        case PPP_STATE_OPENED:
            return;
    }
}

// Range: 0x3A4 -> 0x414
void PAPUp(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_INITIAL:
            break;
        case PPP_STATE_STARTING:
            PPPInitializeRestartCount(conf);
            SendAuthenticateRequest(conf);
            PPPSetState(conf, PPP_STATE_REQ_SENT);
            break;
        case PPP_STATE_CLOSED:
            return;
        case PPP_STATE_STOPPED:
        case PPP_STATE_CLOSING:
        case PPP_STATE_STOPPING:
        case PPP_STATE_REQ_SENT:
        case PPP_STATE_ACK_RCVD:
        case PPP_STATE_ACK_SENT:
        case PPP_STATE_OPENED:
            return;
    }
}

// Range: 0x414 -> 0x4B4
void PAPDown(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_INITIAL:
            break;
        case PPP_STATE_STARTING:
            break;
        case PPP_STATE_CLOSED:
            PPPSetState(conf, PPP_STATE_INITIAL);
            break;
        case PPP_STATE_STOPPED:
            break;
        case PPP_STATE_CLOSING:
            break;
        case PPP_STATE_STOPPING:
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
}

// Range: 0x4B4 -> 0x57C
void PAPClose(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_INITIAL:
            break;
        case PPP_STATE_STARTING:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_CLOSED:
            break;
        case PPP_STATE_STOPPED:
            break;
        case PPP_STATE_CLOSING:
            break;
        case PPP_STATE_STOPPING:
            break;
        case PPP_STATE_REQ_SENT:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_ACK_RCVD:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_ACK_SENT:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
            break;
        case PPP_STATE_OPENED:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerDown(conf);
            PPPLayerFinished(conf);
            break;
    }
}

// Range: 0x57C -> 0x664
int PAPTimeout(PPPConf* conf /* r31 */) {
    // Local variables
    int expired; // r30

    expired = FALSE;
    switch (conf->state) {
        case PPP_STATE_REQ_SENT:
            if (!SendAuthenticateRequest(conf)) {
                expired = TRUE;
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
            }
            break;
        case PPP_STATE_ACK_RCVD:
            if (conf->configure <= 0) {
                expired = TRUE;
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
            }
            break;
        case PPP_STATE_ACK_SENT:
            if (!SendAuthenticateRequest(conf)) {
                expired = TRUE;
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
            }
            break;
        case PPP_STATE_STOPPED:
            (void)0;
            break;
        case PPP_STATE_CLOSING:
        case PPP_STATE_STOPPING:
            (void)0;
            break;
        case PPP_STATE_OPENED:
            break;
    }

    return !expired;
}

// Range: 0x664 -> 0x72C
void PAPIn(PPPConf* conf /* r30 */, PAPHeader* pap /* r31 */, s32 len /* r29 */, u32 flag) {
    if (len < 4 || len < pap->len || pap->len < 4) {
        return;
    }

    switch (pap->code) {
        case 1:
            ReceiveAuthenticateRequest(conf, pap);
            break;
        case 2:
            if (pap->id == conf->id) {
                ReceiveAuthenticateAck(conf, pap);
            }
            break;
        case 3:
            if (pap->id == conf->id) {
                ReceiveAuthenticateNak(conf, pap);
            }
            break;
    }
}

// Range: 0x72C -> 0x734
static int Up() {
    return TRUE;
}

// Range: 0x734 -> 0x75C
static int Down() {
    // References
    // -> PPPAuth __PPPAuth;

    __PPPAuth.messageLen = 0;
    __PPPAuth.message[0] = '\0';
    return TRUE;
}

// Range: 0x75C -> 0x764
static int Started() {
    return TRUE;
}

// Range: 0x764 -> 0x76C
static int Finished() {
    return TRUE;
}

// Range: 0x76C -> 0x7FC
void PAPInit(PPPConf* conf /* r31 */, IPInterface* interface /* r1+0xC */) {
    memset(conf, 0, sizeof(PPPConf));
    conf->protocol = PPP_PAP;
    OSCreateAlarm(&conf->alarm);
    conf->interface = interface;
    conf->state = PPP_STATE_INITIAL;
    conf->up = Up;
    conf->down = Down;
    conf->started = Started;
    conf->finished = Finished;
}
