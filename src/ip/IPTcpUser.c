#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static u16 Port = 0xC000; // size: 0x2, address: 0x0
IFQueue TCPInfoQueue; // size: 0x8, address: 0x0

// Range: 0x0 -> 0x74
void TCPEnumInfoQueue(TCPCallback callback /* r1+0x8 */) {
    // Local variables
    IPInfo* info; // r31
    IPInfo* next; // r30

    // References
    // -> struct IFQueue TCPInfoQueue;

    IFQueueIterator(IPInfo*, &TCPInfoQueue, info, next) {
        callback((TCPInfo*)info, 0);
    }
}

// Range: 0x74 -> 0x78
static void NullCallback() {}

// Range: 0x78 -> 0xA4
static void SyncCallback(TCPInfo* info /* r1+0x8 */, s32) {
    OSWakeupThread(&info->queueThread);
}

// Range: 0xA4 -> 0xEC
TCPInfo* TCPLookupInfo(IPHeader* ip /* r30 */, TCPHeader* tcp /* r31 */) {
    // References
    // -> struct IFQueue TCPInfoQueue;

    return (TCPInfo*)IPLookupInfo(&TCPInfoQueue, ip->src, ip->dst, tcp->src, tcp->dst, 0);
}

// Range: 0xEC -> 0x108
s32 TCPGetStatus(TCPInfo* info /* r3 */) {
    if (info->pair.proto != IP_PROTO_TCP) {
        return -12;
    }
    return info->state;
}

// Range: 0x108 -> 0x16C
s32 TCPGetRemoteSocket(TCPInfo* info /* r29 */, IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = IPGetRemoteSocket(&info->pair, socket);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x16C -> 0x1D0
s32 TCPGetLocalSocket(TCPInfo* info /* r29 */, IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = IPGetLocalSocket(&info->pair, socket);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x1D0 -> 0x27C
s32 TCPBind(TCPInfo* info /* r30 */, const IPSocket* socket /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    // References
    // -> struct IFQueue TCPInfoQueue;

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (info->state != 0) {
        rc = -12;
    } else if (IP_CLASSD(socket->addr)) {
        rc = -13;
    } else {
        rc = IPBind(&TCPInfoQueue, &info->pair, socket, (info->flag & 0x10000) ? TRUE : FALSE);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x27C -> 0x5CC
BOOL TCPAbort(TCPInfo* info /* r31 */) {
    // Local variables
    TCPCallback callbackTable[5]; // r1+0xC
    TCPCallback callback; // r24
    s32 state; // r21
    int i; // r22
    TCPInfo* log; // r23

    // References
    // -> struct IFQueue TCPInfoQueue;

    ASSERTLINE(304, info->pair.proto == IP_PROTO_TCP);
    if (info->pair.proto != IP_PROTO_TCP) {
        return FALSE;
    }

    state = info->state;
    info->state = 0;
    IPCancel(&info->datagram);
    TCPCancelRxmitTimer(info);
    OSCancelAlarm(&info->dackAlarm);
    OSCancelAlarm(&info->lingerAlarm);

    while (info->queueListen.next) {
        log = (TCPInfo*)info->queueListen.next;
        ASSERTLINE(330, log->listening == info);
        ASSERTLINE(331, log->state == TCP_STATE_LISTEN);
        log->err = info->err;
        TCPAbort(log);
    }

    if (info->listening) {
        IFQueueDequeueEntryLINK(TCPInfo*, &info->listening->queueListen, linkListen, info);
        info->listening = NULL;
        ASSERTLINE(342, state == TCP_STATE_LISTEN);
        IFQueueEnqueueHead(IPInfo*, &TCPInfoQueue, &info->pair);
    } else if (state == TCP_STATE_LISTEN) {
        info->openCallback = NullCallback;
    }

    if (info->flag & 1) {
        IFQueueDequeueEntry(IPInfo*, &TCPInfoQueue, &info->pair);
        info->pair.proto = 0;
        IPClose(&info->pair);
    }

    if (info->openResult) {
        *info->openResult = info->err;
        info->openResult = NULL;
    }
    if (info->sendResult) {
        *info->sendResult = info->err;
        info->sendResult = NULL;
    }
    if (info->recvResult) {
        *info->recvResult = info->err;
        info->recvResult = NULL;
    }
    if (info->urgResult) {
        *info->urgResult = info->err;
        info->urgResult = NULL;
    }
    if (info->closeResult) {
        *info->closeResult = 0;
        info->closeResult = NULL;
    }

    callbackTable[0] = info->openCallback;
    info->openCallback = NULL;
    callbackTable[1] = info->sendCallback;
    info->sendCallback = NULL;
    callbackTable[2] = info->recvCallback;
    info->recvCallback = NULL;
    callbackTable[3] = info->urgCallback;
    info->urgCallback = NULL;
    callbackTable[4] = info->closeCallback;
    info->closeCallback = NULL;

    for (i = 0; i < 4; i++) {
        callback = callbackTable[i];
        if (callback) {
            callback(info, info->err);
        }
    }

    callback = callbackTable[4];
    if (callback) {
        callback(info, 0);
    }

    if (info->pair.poll > 0) {
        __IPWakeupPollingThreads();
    }
    return TRUE;
}

// Range: 0x5CC -> 0x688
s32 TCPSetSendBuff(TCPInfo* info /* r31 */, void* sendbuf /* r1+0xC */, s32 sendbufLen /* r30 */) {
    // Local variables
    BOOL enabled; // r28
    s32 rc; // r29

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || info->state != 0 || sendbufLen < 0) {
        rc = -12;
    } else {
        rc = 0;
        info->sendBuff = sendbufLen;
        info->sendPtr = info->sendData = sendbuf;
        sendbufLen = (MIN(info->sendLowat, sendbufLen) < 1) ? 1 : MIN(info->sendLowat, sendbufLen);
        info->sendLowat = sendbufLen;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x688 -> 0x74C
s32 TCPSetRecvBuff(TCPInfo* info /* r31 */, void* recvbuf /* r1+0xC */, s32 recvbufLen /* r30 */) {
    // Local variables
    BOOL enabled; // r28
    s32 rc; // r29

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || info->state != 0 || recvbufLen < 0) {
        rc = -12;
    } else {
        rc = 0;
        info->recvBuff = recvbufLen;
        info->recvPtr = info->recvData = recvbuf;
        info->recvWin = info->recvBuff;
        recvbufLen = (MIN(info->recvLowat, recvbufLen) < 1) ? 1 : MIN(info->recvLowat, recvbufLen);
        info->recvLowat = recvbufLen;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x74C -> 0x7C8
s32 TCPGetSendBuff(TCPInfo* info /* r30 */, void* sendbuf /* r27 */, s32* sendbufLen /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = 0;
        if (sendbufLen) {
            *sendbufLen = info->sendBuff;
        }
        if (sendbuf) {
            *(u8**)sendbuf = info->sendData;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x7C8 -> 0x844
s32 TCPGetRecvBuff(TCPInfo* info /* r30 */, void* recvbuf /* r27 */, s32* recvbufLen /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = 0;
        if (recvbufLen) {
            *recvbufLen = info->recvBuff;
        }
        if (recvbuf) {
            *(u8**)recvbuf = info->recvData;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x844 -> 0xAB0
s32 TCPOpen(TCPInfo* info /* r31 */, void* sendbuf /* r1+0xC */, s32 sendbufLen /* r1+0x10 */, void* recvbuf /* r1+0x14 */, s32 recvbufLen /* r1+0x18 */) {
    // Local variables
    BOOL enabled; // r28
    BOOL used; // r27
    IPHeader* header; // r29

    // References
    // -> struct IFQueue TCPInfoQueue;

    if (info == NULL) {
        return -12;
    }

    enabled = OSDisableInterrupts();
    used = __IPIsMember(&TCPInfoQueue, &info->pair);
    OSRestoreInterrupts(enabled);
    if (used) {
        return -5;
    }

    memset(info, 0, sizeof(TCPInfo));
    info->pair.proto = IP_PROTO_TCP;
    info->pair.tos = 0;
    info->pair.ttl = 255;
    info->pair.mttl = 1;
    info->pair.poll = 0;
    info->pair.flag = 0x8000;
    info->pair.local.len = IP_SOCKLEN;
    info->pair.local.family = IP_INET;
    info->pair.remote.len = IP_SOCKLEN;
    info->pair.remote.family = IP_INET;
    OSInitThreadQueue(&info->queueThread);
    info->state = 0;
    info->err = 0;
    info->mss = 536;
    info->cWin = info->mss * 2;
    info->ssThresh = 65535;
    info->lastSend = OSGetTime();
    info->flag = 0x82;
    info->sendWin = 536;
    TCPSetSendBuff(info, sendbuf, sendbufLen);
    TCPSetRecvBuff(info, recvbuf, recvbufLen);
    info->r2 = OSSecondsToTicks((OSTime)100);
    TCPInitRtt(info);
    OSCreateAlarm(&info->rxmitAlarm);
    OSCreateAlarm(&info->dackAlarm);
    info->linger = 0;
    OSCreateAlarm(&info->lingerAlarm);
    IFQueueInit(&info->queueListen);
    info->sendLowat = 1;
    info->recvLowat = 1;
    IFQueueInit(&info->queueBacklog);
    IFQueueInit(&info->queueCompleted);
    info->accepting = 0;

    header = (IPHeader*)info->header;
    header->verlen = 0x45;
    header->tos = info->pair.tos;
    header->len = IP_HLEN(header) + 20;
    header->ttl = info->pair.ttl;
    header->proto = IP_PROTO_TCP;
    header->frag = 0x4000;

    enabled = OSDisableInterrupts();
    IFQueueEnqueueTail(IPInfo*, &TCPInfoQueue, &info->pair);
    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0xAB0 -> 0xBC0
s32 TCPListen(TCPInfo* info /* r31 */, IPSocket* local /* r1+0xC */, IPSocket* remote /* r1+0x10 */, int (*callback)(TCPInfo*, s32) /* r27 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r28
    s32 rc; // r30

    // References
    // -> static unsigned short Port;
    // -> struct IFQueue TCPInfoQueue;

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (info->state != 0) {
        rc = -5;
    } else {
        if (info->pair.local.port == 0) {
            info->pair.local.port = IPGetAnonPort(&TCPInfoQueue, &Port);
        }
        if (info->pair.local.port == 0) {
            rc = -7;
        } else {
            rc = 0;
            info->state = TCP_STATE_LISTEN;
            info->openCallback = (TCPCallback)(callback ? callback : (int (*)(TCPInfo*, s32))NullCallback);
            info->openResult = result;
            info->local = local;
            info->remote = remote;
            ASSERTLINE(665, info->listening == NULL);
        }
    }
    if (result) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0xBC0 -> 0xD04
s32 TCPAcceptAsync(TCPInfo* info /* r31 */, TCPInfo* listening /* r26 */, TCPCallback callback /* r25 */, s32* result /* r24 */) {
    // Local variables
    BOOL enabled; // r23
    s32 rc; // r27

    // References
    // -> struct IFQueue TCPInfoQueue;

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || info->sendBuff == 0 || info->recvBuff == 0) {
        rc = -12;
    } else if (info->state != 0) {
        rc = -5;
    } else if (listening->state != TCP_STATE_LISTEN) {
        rc = -4;
    } else {
        rc = 0;
        callback = callback ? callback : NullCallback;
        IFQueueDequeueEntry(IPInfo*, &TCPInfoQueue, &info->pair);
        info->listening = listening;
        info->state = TCP_STATE_LISTEN;
        info->openCallback = callback;
        info->openResult = result;
        do {
            register IFQueue* ___prev;

            ___prev = listening->queueListen.prev;
            if (___prev == 0) {
                listening->queueListen.next = (IFQueue*)info;
            } else {
                ((TCPInfo*)___prev)->linkListen.next = (IFQueue*)info;
            }
            info->linkListen.prev = ___prev;
            info->linkListen.next = 0;
            listening->queueListen.prev = (IFQueue*)info;
        } while (0);
    }
    if (result) {
        *result = (rc == 0) ? IP_ERR_BUSY : rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0xD04 -> 0xD88
s32 TCPAccept(TCPInfo* info /* r29 */, TCPInfo* listening /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x10
    s32 rc; // r31

    rc = TCPAcceptAsync(info, listening, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0xD88 -> 0xF38
s32 TCPConnectAsync(TCPInfo* info /* r31 */, const IPSocket* socket /* r24 */, TCPCallback callback /* r28 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r25
    IPHeader* header; // r27
    s32 rc; // r30
    IPInterface* interface; // r26

    // References
    // -> static unsigned short Port;
    // -> struct IFQueue TCPInfoQueue;

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || info->sendBuff == 0 || info->recvBuff == 0) {
        rc = -12;
    } else if (info->state != 0) {
        rc = -5;
    } else if ((rc = IPConnect(&TCPInfoQueue, &info->pair, socket, &Port)) == 0) {
        callback = callback ? callback : NullCallback;
        header = (IPHeader*)info->header;
        memmove(header->dst, info->pair.remote.addr, 4);
        memmove(header->src, info->pair.local.addr, 4);
        interface = IPGetRoute(socket->addr, NULL);
        ASSERTLINE(776, interface);
        info->mss = interface->mtu - 40;
        info->openCallback = callback;
        info->openResult = result;
        info->iss = TCPIsn(&info->pair);
        info->sendUna = info->iss;
        info->sendNext = info->iss;
        info->sendMax = info->iss;
        info->sendUp = info->sendUna;
        info->state = 2;
        info->sendRecover = info->sendUna;
        info->sendFack = info->sendUna;
        info->lastSack = info->sendUna;
        info->rxmitData = 0;
        info->sendAwin = 0;
        if (result) {
            *result = IP_ERR_BUSY;
        }
        TCPOutput(info, 0);
    }
    if (result && rc < 0) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0xF38 -> 0xFBC
s32 TCPConnect(TCPInfo* info /* r29 */, const IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x10
    s32 rc; // r31

    rc = TCPConnectAsync(info, socket, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0xFBC -> 0x1200
static s32 SendAsync(TCPInfo* info /* r31 */, void* data /* r1+0xC */, s32 len /* r26 */, u32 flag /* r27 */, TCPCallback callback /* r28 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r25
    s32 rc; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || len < 0) {
        rc = -12;
    } else if (info->sendCallback) {
        rc = IP_ERR_BUSY;
    } else if ((flag & 1) && len == 0) {
        rc = -12;
    } else {
        callback = callback ? callback : NullCallback;
        switch (info->state) {
            case 0:
                rc = -4;
                break;
            case 1:
                rc = -6;
                break;
            case 2:
            case 3:
            case 4:
            case 7:
                if (info->flag & 0x8) {
                    rc = -8;
                    break;
                }
                info->userAcked = 0;
                info->userSendData = data;
                info->userSendLen = len;
                info->sendCallback = callback;
                info->sendResult = result;
                if (result) {
                    *result = IP_ERR_BUSY;
                }
                rc = TCPSendIn(info, flag & 4);
                if (flag & 1) {
                    info->sendUp = info->sendUna + info->sendLen + info->userSendLen;
                    if (info->state < 4 && info->iss == info->sendUna) {
                        info->sendUp++;
                    }
                }
                if (info->userSendLen <= 0 || (flag & 4)) {
                    info->userSendLen = 0;
                    if (info->sendResult) {
                        ASSERTLINE(912, rc == info->userAcked);
                        *info->sendResult = rc;
                        info->sendResult = NULL;
                    }
                    info->sendCallback = NULL;
                    callback(info, info->userAcked);
                }
                if (info->state == 4 || info->state == 7) {
                    TCPOutput(info, 0);
                }
                break;
            case 5:
            case 6:
            case 8:
            case 9:
            case 10:
            default:
                rc = -8;
                break;
        }
    }
    if (result && rc < 0) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x1200 -> 0x124C
s32 TCPSendAsync(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, TCPCallback callback /* r1+0x14 */, s32* result /* r1+0x18 */) {
    return SendAsync(info, data, len, 0, callback, result);
}

// Range: 0x124C -> 0x12C0
s32 TCPSendNonblock(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r30 */) {
    // Local variables
    s32 result; // r1+0x14
    s32 rc; // r31

    rc = SendAsync(info, data, len, 4, NULL, &result);
    if (rc == 0) {
        rc = result;
    }
    if (rc == 0 && len > 0) {
        rc = -9;
    }
    return rc;
}

// Range: 0x12C0 -> 0x130C
s32 TCPSendUrgAsync(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, TCPCallback callback /* r1+0x14 */, s32* result /* r1+0x18 */) {
    return SendAsync(info, data, len, 1, callback, result);
}

// Range: 0x130C -> 0x1380
s32 TCPSendUrgNonblock(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r30 */) {
    // Local variables
    s32 result; // r1+0x14
    s32 rc; // r31

    rc = SendAsync(info, data, len, 5, NULL, &result);
    if (rc == 0) {
        rc = result;
    }
    if (rc == 0 && len > 0) {
        rc = -9;
    }
    return rc;
}

// Range: 0x1380 -> 0x1414
static s32 Send(TCPInfo* info /* r29 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, u32 flag /* r1+0x14 */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x18
    s32 rc; // r31

    rc = SendAsync(info, data, len, flag, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1414 -> 0x1450
s32 TCPSend(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    return Send(info, data, len, 0);
}

// Range: 0x1450 -> 0x148C
s32 TCPSendUrg(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    return Send(info, data, len, 1);
}

// Range: 0x148C -> 0x17B8
s32 TCPReceiveExAsync(TCPInfo* info /* r30 */, void* data /* r24 */, s32 len /* r26 */, u32 flag /* r27 */, TCPCallback callback /* r28 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r25
    int rc; // r31
    BOOL urgent; // r1+0x20

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || len < 0) {
        rc = -12;
    } else if (info->recvCallback && !(flag & 4)) {
        rc = IP_ERR_BUSY;
    } else if (info->flag & 0x11) {
        rc = -8;
    } else {
        rc = 0;
        callback = callback ? callback : NullCallback;
        switch (info->state) {
            case 0:
                if (info->flag & 0x8) {
                    rc = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                } else {
                    rc = -4;
                }
                break;
            case 1:
            case 2:
            case 3:
                if (len == 0) {
                    rc = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                    break;
                }
                if (flag & 4) {
                    rc = -9;
                    break;
                }
                if (flag & 2) {
                    info->flag |= 0x400;
                } else {
                    info->flag &= ~0x400;
                }
                info->userData = data;
                info->userBuff = len;
                info->userLen = 0;
                info->recvCallback = callback;
                info->recvResult = result;
                if (result) {
                    *result = IP_ERR_BUSY;
                }
                break;
            case 4:
            case 5:
            case 6:
            case 7:
                if (len == 0) {
                    rc = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                    break;
                }
                if (flag & 2) {
                    info->flag |= 0x400;
                } else {
                    info->flag &= ~0x400;
                }
                info->userData = data;
                info->userBuff = len;
                info->userLen = 0;
                rc = TCPRecvOut(info, &urgent);
                if (info->recvLowat <= rc || (0 < rc && (urgent || (flag & 4)))) {
                    info->userLen = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                    TCPOutput(info, 0);
                    break;
                }
                if (info->state == 7 && info->recvUser == 0) {
                    rc = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                    break;
                }
                if (flag & 4) {
                    rc = -9;
                    break;
                }
                rc = 0;
                info->recvCallback = callback;
                info->recvResult = result;
                if (result) {
                    *result = IP_ERR_BUSY;
                }
                break;
            case 8:
            case 9:
            case 10:
            default:
                rc = 0;
                if (result) {
                    *result = rc;
                }
                callback(info, rc);
                break;
        }
    }
    if (result && rc < 0) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x17B8 -> 0x184C
s32 TCPReceiveEx(TCPInfo* info /* r29 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, u32 flag /* r1+0x14 */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x18
    s32 rc; // r31

    rc = TCPReceiveExAsync(info, data, len, flag, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x184C -> 0x1898
s32 TCPReceiveAsync(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, TCPCallback callback /* r1+0x14 */, s32* result /* r1+0x18 */) {
    return TCPReceiveExAsync(info, data, len, 0, callback, result);
}

// Range: 0x1898 -> 0x18FC
s32 TCPReceiveNonblock(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    // Local variables
    s32 rc; // r31
    s32 result; // r1+0x14

    rc = TCPReceiveExAsync(info, data, len, 4, NULL, &result);
    if (rc == 0) {
        return result;
    }
    return rc;
}

// Range: 0x18FC -> 0x1938
s32 TCPReceive(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    return TCPReceiveEx(info, data, len, 0);
}

// Range: 0x1938 -> 0x1A48
s32 TCPPeek(TCPInfo* info /* r30 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r29
    int rc; // r31
    BOOL urgent; // r1+0x14

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (info->flag & 0x11) {
        rc = -8;
    } else {
        switch (info->state) {
            case 0:
                if (info->flag & 0x8) {
                    rc = 0;
                } else {
                    rc = -4;
                }
                break;
            case 1:
            case 2:
            case 3:
                rc = 0;
                break;
            case 4:
            case 5:
            case 6:
            case 7:
                rc = TCPPeekOut(info, data, len, TRUE, &urgent);
                if (rc <= 0) {
                    if (info->state == 7 && info->recvUser == 0) {
                        rc = 0;
                    } else {
                        rc = -9;
                    }
                }
                break;
            case 8:
            case 9:
            case 10:
            default:
                rc = 0;
                break;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x1A48 -> 0x1BF4
s32 TCPCloseAsync(TCPInfo* info /* r31 */, TCPCallback callback /* r28 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r27
    s32 rc; // r30

    enabled = OSDisableInterrupts();
    callback = callback ? callback : NullCallback;
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (info->flag & 1) {
        rc = -8;
    } else if (info->recvUser > 0) {
        info->closeCallback = callback;
        info->closeResult = result;
        if (result) {
            *result = IP_ERR_BUSY;
        }
        rc = TCPCancel(info);
    } else {
        ASSERTLINE(1337, info->closeCallback == NULL);
        rc = 0;
        info->flag |= 0x19;
        info->closeCallback = callback;
        info->closeResult = result;
        if (result) {
            *result = IP_ERR_BUSY;
        }
        switch (info->state) {
            case 0:
            case 1:
            case 2:
                info->err = -8;
                TCPAbort(info);
                break;
            case 3:
                break;
            case 4:
                info->state = 5;
                TCPOutput(info, 0);
                break;
            case 5:
            case 6:
                break;
            case 7:
                info->state = 9;
                TCPOutput(info, 0);
                break;
            case 8:
            case 9:
            case 10:
                break;
            default:
                rc = -12;
                break;
        }
        if (info->pair.poll > 0) {
            __IPWakeupPollingThreads();
        }
    }
    if (result && rc < 0) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x1BF4 -> 0x1C70
s32 TCPClose(TCPInfo* info /* r29 */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0xC
    s32 rc; // r31

    rc = TCPCloseAsync(info, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x1C70 -> 0x1F58
s32 TCPShutdown(TCPInfo* info /* r31 */, u32 flag /* r25 */) {
    // Local variables
    BOOL enabled; // r26
    BOOL output; // r28
    s32 rcSend; // r29
    s32 rcRecv; // r27
    TCPCallback callback; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        OSRestoreInterrupts(enabled);
        return -12;
    }

    output = FALSE;
    rcRecv = 0;
    rcSend = 0;
    if (flag == 0 || flag == 2) {
        if (info->recvUser > 0) {
            TCPCancel(info);
            OSRestoreInterrupts(enabled);
            return -8;
        }
        info->flag |= 0x10;
        switch (info->state) {
            case 0:
                rcRecv = -4;
                break;
            case 1:
            case 2:
            case 3:
                callback = info->recvCallback;
                if (callback) {
                    if (info->recvResult) {
                        *info->recvResult = -8;
                        info->recvResult = NULL;
                    }
                    info->recvCallback = NULL;
                    callback(info, -8);
                }
                callback = info->urgCallback;
                if (callback) {
                    if (info->urgResult) {
                        *info->urgResult = -8;
                        info->urgResult = NULL;
                    }
                    info->urgCallback = NULL;
                    callback(info, -8);
                }
                info->recvUser = 0;
                break;
            case 4:
            case 5:
            case 6:
            case 7:
                callback = info->recvCallback;
                if (callback) {
                    if (info->recvResult) {
                        *info->recvResult = -8;
                        info->recvResult = NULL;
                    }
                    info->recvCallback = NULL;
                    callback(info, -8);
                }
                callback = info->urgCallback;
                if (callback) {
                    if (info->urgResult) {
                        *info->urgResult = -8;
                        info->urgResult = NULL;
                    }
                    info->urgCallback = NULL;
                    callback(info, -8);
                }
                if (info->recvUser > 0) {
                    info->recvUser = 0;
                    output = TRUE;
                }
                break;
            case 8:
            case 9:
            case 10:
            default:
                rcRecv = -8;
                break;
        }
    }

    if (flag == 1 || flag == 2) {
        info->flag |= 0x8;
        switch (info->state) {
            case 0:
                rcSend = -4;
                break;
            case 1:
            case 2:
                info->err = -8;
                TCPAbort(info);
                break;
            case 3:
                break;
            case 4:
                info->state = 5;
                output = TRUE;
                break;
            case 5:
            case 6:
                rcSend = -8;
                break;
            case 7:
                info->state = 9;
                output = TRUE;
                break;
            case 8:
            case 9:
            case 10:
            default:
                rcSend = -8;
                break;
        }
        if (info->pair.poll > 0) {
            __IPWakeupPollingThreads();
        }
    }

    if (output) {
        TCPOutput(info, 0);
    }
    OSRestoreInterrupts(enabled);
    return MIN(rcSend, rcRecv);
}

// Range: 0x1F58 -> 0x2034
s32 TCPCancel(TCPInfo* info /* r31 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = 0;
        info->flag |= 0x18;
        info->err = -3;
        switch (info->state) {
            case 0:
            case 1:
            case 2:
            case 8:
            case 9:
            case 10:
                break;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                TCPRespond(info->interface, NULL, info->pair.remote.addr, info->pair.remote.port, info->pair.local.addr, info->pair.local.port, info->sendMax, 0, TCP_FLAG_RST, 0);
                break;
        }
        info->flag |= 1;
        TCPAbort(info);
        if (info->pair.poll > 0) {
            __IPWakeupPollingThreads();
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x2034 -> 0x22D4
s32 TCPReceiveUrgExAsync(TCPInfo* info /* r31 */, void* data /* r26 */, s32 len /* r1+0x10 */, u32 flag /* r27 */, TCPCallback callback /* r28 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r25
    int rc; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || len < 1) {
        rc = -12;
    } else if (info->urgCallback) {
        rc = IP_ERR_BUSY;
    } else if (info->flag & 0x11) {
        rc = -8;
    } else {
        rc = 0;
        callback = callback ? callback : NullCallback;
        switch (info->state) {
            case 0:
                if (info->flag & 0x8) {
                    rc = 0;
                } else {
                    rc = -4;
                }
                break;
            case 1:
            case 2:
            case 3:
                if (flag & 4) {
                    rc = -12;
                    break;
                }
                if (flag & 2) {
                    info->flag |= 0x800;
                } else {
                    info->flag &= ~0x800;
                }
                info->urgData = data;
                info->urgCallback = callback;
                info->urgResult = result;
                if (result) {
                    *result = IP_ERR_BUSY;
                }
                break;
            case 4:
            case 5:
            case 6:
            case 7:
                if (flag & 2) {
                    info->flag |= 0x800;
                } else {
                    info->flag &= ~0x800;
                }
                info->urgData = data;
                if ((info->recvUrg > 0 || (info->flag & 0x20)) && !(info->flag & 0x40)) {
                    if (info->flag & 0x20) {
                        rc = 1;
                        if (data) {
                            *info->urgData = info->oob;
                        }
                        if (info->flag & 0x800) {
                            info->flag ^= 0x60;
                        }
                        if (result) {
                            *result = rc;
                        }
                        callback(info, rc);
                    } else {
                        rc = -9;
                    }
                    break;
                }
                if (info->state == 7) {
                    rc = 0;
                    if (result) {
                        *result = rc;
                    }
                    callback(info, rc);
                    break;
                }
                if (flag & 4) {
                    rc = -12;
                    break;
                }
                rc = 0;
                info->urgCallback = callback;
                info->urgResult = result;
                if (result) {
                    *result = IP_ERR_BUSY;
                }
                break;
            case 8:
            case 9:
            case 10:
            default:
                rc = 0;
                if (result) {
                    *result = rc;
                }
                callback(info, rc);
                break;
        }
    }
    if (result && rc < 0) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x22D4 -> 0x2320
s32 TCPReceiveUrgAsync(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, TCPCallback callback /* r1+0x14 */, s32* result /* r1+0x18 */) {
    return TCPReceiveUrgExAsync(info, data, len, 1, callback, result);
}

// Range: 0x2320 -> 0x2384
s32 TCPReceiveUrgNonblock(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    // Local variables
    s32 rc; // r31
    s32 result; // r1+0x14

    rc = TCPReceiveUrgExAsync(info, data, len, 5, NULL, &result);
    if (rc == 0) {
        return result;
    }
    return rc;
}

// Range: 0x2384 -> 0x2418
s32 TCPReceiveUrgEx(TCPInfo* info /* r29 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, u32 flags /* r1+0x14 */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x18
    s32 rc; // r31

    rc = TCPReceiveUrgExAsync(info, data, len, flags, SyncCallback, &result);
    if (rc < 0) {
        return rc;
    }
    enabled = OSDisableInterrupts();
    while (result == IP_ERR_BUSY) {
        OSSleepThread(&info->queueThread);
    }
    OSRestoreInterrupts(enabled);
    return result;
}

// Range: 0x2418 -> 0x2454
s32 TCPReceiveUrg(TCPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */) {
    return TCPReceiveUrgEx(info, data, len, 0);
}

// Range: 0x2454 -> 0x2590
s32 TCPPeekUrg(TCPInfo* info /* r30 */, void* data /* r28 */, s32 len /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r29
    int rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP || len < 1) {
        rc = -12;
    } else if (info->flag & 0x11) {
        rc = -8;
    } else {
        switch (info->state) {
            case 0:
                if (info->flag & 0x8) {
                    rc = 0;
                } else {
                    rc = -4;
                }
                break;
            case 1:
            case 2:
            case 3:
                rc = -12;
                break;
            case 4:
            case 5:
            case 6:
            case 7:
                if ((info->recvUrg > 0 || (info->flag & 0x20)) && !(info->flag & 0x40)) {
                    if (info->flag & 0x20) {
                        rc = 1;
                        if (data) {
                            *(u8*)data = info->oob;
                        }
                    } else {
                        rc = -9;
                    }
                } else if (info->state == 7) {
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 8:
            case 9:
            case 10:
            default:
                rc = 0;
                break;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x2590 -> 0x25E4
s32 TCPGetUrgOffset(TCPInfo* info /* r29 */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = info->recvUrg;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x25E4 -> 0x289C
s32 TCPGetSockOpt(TCPInfo* info /* r29 */, int level /* r27 */, int optname /* r25 */, void* optval /* r28 */, int* optlen /* r30 */) {
    // Local variables
    BOOL enabled; // r24
    s32 rc; // r31
    SOLinger* linger; // r26

    rc = -14;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (level == 0xFFFF) {
        switch (optname) {
            case 0x4:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = (info->flag & 0x10000) ? 1 : 0;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x100:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = (info->flag & 0x80) ? 0 : 1;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1008:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = 1;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x80:
                if (*optlen >= sizeof(SOLinger)) {
                    linger = (SOLinger*)optval;
                    linger->onoff = (info->flag & 0x20000) ? 1 : 0;
                    linger->linger = info->linger;
                    *optlen = sizeof(SOLinger);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1003:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = info->sendLowat;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1004:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = info->recvLowat;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
        }
    } else if (level == 0) {
        rc = IPGetSockOpt(&info->pair, level, optname, optval, optlen);
    } else if (level == 6) {
        switch (optname) {
            case 0x2001:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = (info->flag & 0x2) ? 0 : 1;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x2002:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = info->mss;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x289C -> 0x2B50
s32 TCPSetSockOpt(TCPInfo* info /* r31 */, int level /* r24 */, int optname /* r23 */, void* optval /* r28 */, int optlen /* r29 */) {
    // Local variables
    BOOL enabled; // r22
    s32 rc; // r30
    const SOLinger* linger; // r25

    rc = -14;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else if (level == 0xFFFF) {
        switch (optname) {
            case 0x4:
                if (optlen >= sizeof(int)) {
                    if (*(int*)optval) {
                        info->flag |= 0x10000;
                    } else {
                        info->flag &= ~0x10000;
                    }
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x100:
                if (optlen >= sizeof(int)) {
                    if (*(int*)optval) {
                        info->flag &= ~0x80;
                    } else {
                        info->flag |= 0x80;
                    }
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x80:
                if (optlen >= sizeof(SOLinger)) {
                    linger = (const SOLinger*)optval;
                    if (linger->onoff) {
                        info->flag |= 0x20000;
                    } else {
                        info->flag &= ~0x20000;
                    }
                    info->linger = (0 < linger->linger) ? linger->linger : 0;
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1003:
                if (optlen >= sizeof(int)) {
                    int lowat; // r27

                    lowat = *(int*)optval;
                    info->sendLowat = (MIN(info->sendBuff, lowat) < 1) ? 1 : MIN(info->sendBuff, lowat);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1004:
                if (optlen >= sizeof(int)) {
                    int lowat; // r26

                    lowat = *(int*)optval;
                    info->recvLowat = (MIN(info->recvBuff, lowat) < 1) ? 1 : MIN(info->recvBuff, lowat);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
        }
    } else if (level == 0) {
        rc = IPSetSockOpt(&info->pair, level, optname, optval, optlen);
    } else if (level == 6) {
        switch (optname) {
            case 0x2001:
                if (optlen >= sizeof(int)) {
                    if (*(int*)optval) {
                        info->flag &= ~0x2;
                    } else {
                        info->flag |= 0x2;
                    }
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x2B50 -> 0x2BBC
s32 TCPSetTimeout(TCPInfo* info /* r29 */, OSTime threshold /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        info->r2 = threshold;
        rc = 0;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x2BBC -> 0x2BF8
s32 TCPControlNagle(TCPInfo* info /* r1+0x8 */, BOOL enable /* r1+0xC */) {
    return TCPSetSockOpt(info, 6, 0x2001, &enable, sizeof(enable));
}

// Range: 0x2BF8 -> 0x2C38
s32 TCPSetUrgInLine(TCPInfo* info /* r1+0x8 */, BOOL inLine /* r1+0xC */) {
    return TCPSetSockOpt(info, 0xFFFF, 0x100, &inLine, sizeof(inLine));
}

// Range: 0x2C38 -> 0x2CA4
s32 TCPSetOption(TCPInfo* info /* r29 */, u8 ttl /* r1+0xC */, u8 tos /* r1+0xD */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_TCP) {
        rc = -12;
    } else {
        rc = IPSetOption(&info->pair, ttl, tos);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x2CA4 -> 0x2CF8
BOOL TCPOnReset(BOOL) {
    // Local variables
    TCPInfo* info; // r31

    // References
    // -> struct IFQueue TCPInfoQueue;

    if (IFIsEmptyQueue(&TCPInfoQueue)) {
        return TRUE;
    }
    while (!IFIsEmptyQueue(&TCPInfoQueue)) {
        info = (TCPInfo*)TCPInfoQueue.next;
        TCPCancel(info);
    }
    return FALSE;
}

// Range: 0x2CF8 -> 0x2E9C
s16 __TCPPoll(TCPInfo* info /* r3 */) {
    // Local variables
    s16 event; // r31

    if (info->pair.proto != IP_PROTO_TCP) {
        return 0x80;
    }

    event = 0;
    if (info->state == TCP_STATE_LISTEN && info->queueCompleted.next) {
        event |= 0x1;
    }

    switch (info->state) {
        case 0:
            event |= 0x8;
            break;
        case 1:
            break;
        case 2:
        case 3:
        case 4:
        case 7:
            if (info->userSendLen <= 0 && info->sendLowat <= info->sendBuff - info->sendLen) {
                event |= 0x18;
            }
            break;
        case 5:
        case 6:
        case 8:
        case 9:
        case 10:
        default:
            event |= 0x8;
            break;
    }

    switch (info->state) {
        case 0:
            event |= 0x1;
            break;
        case 1:
        case 2:
        case 3:
            break;
        case 4:
        case 5:
        case 6:
        case 7:
            if (info->recvLowat <= info->recvUser) {
                event |= 0x1;
            } else if (info->state == 7) {
                event |= 0x1;
            }
            if ((info->recvUrg > 0 || (info->flag & 0x20)) && !(info->flag & 0x40)) {
                event |= 0x2;
                if (0 < info->recvUser) {
                    event |= 0x1;
                }
            }
            break;
        case 8:
        case 9:
        case 10:
        default:
            event |= 0x1;
            break;
    }

    if (info->flag & 0x8) {
        event |= 0x8;
    }
    if (info->flag & 0x10) {
        event |= 0x1;
    }
    if (info->state == 0 && (info->flag & 0x18) == 0x18 && info->err != 0) {
        event |= 0x20;
    }
    return event;
}
