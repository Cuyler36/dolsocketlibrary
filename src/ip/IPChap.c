#include <dolphin/ip.h>
#include <dolphin/private/ip.h>
#include <dolphin/md5.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

// Range: 0x0 -> 0xB8
static void CHAPOut(IPInterface* interface /* r29 */, CHAPHeader* chap /* r30 */) {
    // Local variables
    BOOL enabled; // r28
    IFDatagram* datagram; // r31

    enabled = OSDisableInterrupts();

    datagram = (IFDatagram*)interface->alloc(interface, sizeof(IFDatagram) + sizeof(u16) + chap->len);
    if (datagram != NULL) {
        IFInitDatagram(datagram, 0x8864, 1);
        *(u16*)((u8*)datagram + sizeof(IFDatagram)) = 0xC223;
        memmove((u8*)datagram + sizeof(IFDatagram) + 2, chap, chap->len);
        datagram->vec[0].data = (u8*)datagram + sizeof(IFDatagram);
        datagram->vec[0].len = chap->len + 2;
        interface->out(interface, datagram);
    }

    OSRestoreInterrupts(enabled);
}

// Range: 0xB8 -> 0x1B0
static int ReceiveChallenge(PPPConf* conf /* r29 */, CHAPHeader* chap /* r31 */) {
    // Local variables
    u32 challengelen; // r30
    MD5Context context; // r1+0x10

    conf->id = chap->id;
    challengelen = *((u8*)chap + 4);
    if (chap->len < sizeof(CHAPHeader) + 1 + challengelen) {
        return FALSE;
    }

    chap->code = 2;
    chap->len = sizeof(CHAPHeader) + 1 + 16 + __PPPAuth.peerIdLen;
    *((u8*)chap + 4) = 16;
    MD5Init(&context);
    MD5Update(&context, &chap->id, 1);
    MD5Update(&context, (u8*)__PPPAuth.password, __PPPAuth.passwordLen);
    MD5Update(&context, (u8*)chap + 5, challengelen);
    MD5Final((u8*)chap + 5, &context);
    memmove((u8*)chap + 5 + 16, __PPPAuth.peerId, __PPPAuth.peerIdLen);
    CHAPOut(conf->interface, chap);
    return TRUE;
}

// Range: 0x1B0 -> 0x1B8
static int ReceiveResponse(PPPConf* conf /* unused */, CHAPHeader* chap /* unused */) {
    return TRUE;
}

// Range: 0x1B8 -> 0x250
static void GetAuthenticateMessage(CHAPHeader* chap /* r31 */) {
    // Local variables
    char* msg; // r30

    msg = (char*)(chap+1);
    __PPPAuth.messageLen = (chap->len - 4) > 255 ? 255 : (chap->len - 4);
    memcpy(__PPPAuth.message, msg, __PPPAuth.messageLen);
    __PPPAuth.message[__PPPAuth.messageLen] = '\0';
}

// Range: 0x250 -> 0x29C
static int ReceiveSuccess(PPPConf* conf /* r31 */, CHAPHeader* chap /* r1+0xC */) {
    GetAuthenticateMessage(chap);
    PPPSetState(conf, PPP_STATE_OPENED);
    PPPLayerUp(conf);
    return TRUE;
}

// Range: 0x29C -> 0x2F4
static int ReceiveFailure(PPPConf* conf /* r31 */, CHAPHeader* chap /* r1+0xC */) {
    GetAuthenticateMessage(chap);
    IPSetConfigError(NULL, -108);
    PPPSetState(conf, PPP_STATE_CLOSED);
    PPPLayerFinished(conf);
    return TRUE;
}

// Range: 0x2F4 -> 0x370
void CHAPOpen(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_INITIAL:
            PPPSetState(conf, PPP_STATE_STARTING);
            PPPLayerStarted(conf);
            break;
        case PPP_STATE_CLOSED:
            PPPInitializeRestartCount(conf);
            PPPSetState(conf, PPP_STATE_ACK_SENT);
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

// Range: 0x370 -> 0x3D8
void CHAPUp(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_STARTING:
            PPPInitializeRestartCount(conf);
            PPPSetState(conf, PPP_STATE_ACK_SENT);
            break;
        case PPP_STATE_INITIAL:
            return;
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

// Range: 0x3D8 -> 0x478
void CHAPDown(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_CLOSED:
            PPPSetState(conf, PPP_STATE_INITIAL);
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
        case PPP_STATE_INITIAL:
        case PPP_STATE_STARTING:
        case PPP_STATE_STOPPED:
        case PPP_STATE_CLOSING:
        case PPP_STATE_STOPPING:
            return;
    }
}

// Range: 0x478 -> 0x540
void CHAPClose(PPPConf* conf /* r31 */) {
    switch (conf->state) {
        case PPP_STATE_STARTING:
            PPPSetState(conf, PPP_STATE_CLOSED);
            PPPLayerFinished(conf);
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
        case PPP_STATE_INITIAL:
        case PPP_STATE_CLOSED:
        case PPP_STATE_STOPPED:
        case PPP_STATE_CLOSING:
        case PPP_STATE_STOPPING:
            return;
    }
}

// Range: 0x540 -> 0x5F0
int CHAPTimeout(PPPConf* conf /* r31 */) {
    // Local variables
    int expired; // r30

    expired = FALSE;
    switch (conf->state) {
        case PPP_STATE_STOPPING:
        case PPP_STATE_REQ_SENT:
        case PPP_STATE_OPENED:
        case PPP_STATE_CLOSED:
        case PPP_STATE_STARTING:
            break;
        case PPP_STATE_ACK_RCVD:
            if (conf->configure <= 0) {
                expired = TRUE;
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
            }
            break;
        case PPP_STATE_ACK_SENT:
            if (conf->configure <= 0) {
                expired = TRUE;
                PPPSetState(conf, PPP_STATE_CLOSED);
                PPPLayerFinished(conf);
            }
            break;
    }

    return !expired;
}

// Range: 0x5F0 -> 0x6DC
void CHAPIn(PPPConf* conf /* r30 */, CHAPHeader* chap /* r31 */, s32 len /* r29 */, u32) {
    if (len < 4 || len < chap->len || chap->len < sizeof(CHAPHeader)) {
        return;
    }

    switch (chap->code) {
        case 1:
            ReceiveChallenge(conf, chap);
            break;
        case 2:
            if (conf->id == chap->id) {
                ReceiveResponse(conf, chap);
            }
            break;
        case 3:
            if (conf->id == chap->id) {
                ReceiveSuccess(conf, chap);
            }
            break;
        case 4:
            if (conf->id == chap->id) {
                ReceiveFailure(conf, chap);
            }
            break;
    }
}

// Range: 0x6DC -> 0x6E4
static int Up() {
    return TRUE;
}

// Range: 0x6E4 -> 0x70C
static int Down() {
    __PPPAuth.messageLen = 0;
    __PPPAuth.message[0] = '\0';
    return TRUE;
}

// Range: 0x70C -> 0x714
static int Started() {
    return TRUE;
}

// Range: 0x714 -> 0x71C
static int Finished() {
    return TRUE;
}

// Range: 0x71C -> 0x7AC
void CHAPInit(PPPConf* conf /* r31 */, IPInterface* interface /* r1+0xC */) {
    memset(conf, 0, sizeof(PPPConf));
    conf->protocol = 0xC223;
    OSCreateAlarm(&conf->alarm);
    conf->interface = interface;
    conf->state = PPP_STATE_INITIAL;
    conf->up = Up;
    conf->down = Down;
    conf->started = Started;
    conf->finished = Finished;
}
