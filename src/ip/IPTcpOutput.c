#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

#define TCP_RXMIT_THRESH 3
#define TCP_FLAG_793 (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_URG)

#define SEQ_LT(a, b) ((s32)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((s32)((a) - (b)) <= 0)
#define SEQ_GT(a, b) ((s32)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((s32)((a) - (b)) >= 0)

static void TCPOutputCallback(TCPInfo* info, s32 result);

// Range: 0x0 -> 0xB8
TCPSackHole* TCPSackOutput(const TCPInfo* info /* r30 */) {
    // Local variables
    const TCPSackHole* hole; // r31
    const TCPSackHole* holeEnd; // r29

    ASSERTLINE(123, TCP_RXMIT_THRESH <= info->dupAcks);
    holeEnd = &info->scoreboard[info->sendHoles];
    for (hole = info->scoreboard; hole < holeEnd; hole++) {
        if (SEQ_GT(hole->end, hole->rxmit) && ((info->flag & 0x1000) || TCP_RXMIT_THRESH <= hole->dupAcks) && SEQ_LEQ(info->sendUna, hole->rxmit)) {
            return (TCPSackHole*)hole;
        }
    }
    return NULL;
}

// Range: 0xB8 -> 0x328
int TCPMakeOption(TCPHeader* tcp /* r25 */, TCPInfo* info /* r29 */, u16 flag /* r1+0x10 */) {
    // Local variables
    int optlen; // r27
    int padding; // r24
    u8* opt; // r31
    IFBlock* block; // r26
    s32* edge = NULL; // r30


    if (info == NULL) {
        tcp->flag &= ~0xF000;
        tcp->flag |= (TCP_MIN_HLEN / 4) << 12;
        return 0;
    }

    opt = (u8*)tcp + TCP_MIN_HLEN;
    if (flag & TCP_FLAG_SYN) {
        *opt++ = 2;
        *opt++ = 4;
        *(u16*)opt = (u16)info->mss;
        opt += 2;
        *opt++ = 4;
        *opt++ = 2;
    }

    if ((info->flag & 0x2000) && info->asb[0].ptr) {
        while ((opt - (u8*)tcp) % 4 != 2) {
            *opt++ = 1;
        }
        opt[0] = 5;
        edge = (s32*)(opt + 2);
        for (block = &info->asb[3]; info->asb <= block; block--) {
            if (block->ptr) {
                if (info->recvPtr <= block->ptr) {
                    edge[0] = block->ptr - info->recvPtr;
                } else {
                    edge[0] = block->ptr + info->recvBuff - info->recvPtr;
                }
                edge[0] += info->recvNext - info->recvUser;
                edge[1] = edge[0] + block->len;
                edge = edge + 2;
            }
        }
        ASSERTLINE(203, (u8*) edge - opt <= 4 * 2 * sizeof(s32) + 2);
        opt[1] = (u8)((u8*)edge - opt);
        opt = (u8*)edge;
    }

    optlen = opt - ((u8*)tcp + TCP_MIN_HLEN);
    if (optlen % 4 != 0) {
        padding = 4 - optlen % 4;
        *opt++ = 0;
        memset(opt, 1, padding - 1);
        optlen += padding;
    }
    ASSERTLINE(217, optlen % 4 == 0);
    ASSERTLINE(218, TCP_MIN_HLEN + optlen <= TCP_MAX_HLEN);
    tcp->flag &= ~0xF000;
    tcp->flag |= (TCP_MIN_HLEN + optlen) << 10;
    return optlen;
}

// Range: 0x328 -> 0x6B8
static s32 TCPCalcSendSize(TCPInfo* info /* r31 */, s32 effSendMss /* r20 */, u16* pflag /* r21 */, s32* poffset /* r1+0x14 */, TCPSackHole* hole /* r28 */) {
    // Local variables
    u16 flag; // r29
    s32 win; // r25
    s32 useable; // r24
    s32 offset; // r23
    s32 dataLen; // r30
    s32 end; // r22
    s32 sendSize; // r26

    flag = *pflag;
    ASSERTLINE(238, 0 <= info->sendLen);

again:
    dataLen = 0;
    switch (info->state) {
        case 2:
        case 3:
            if (info->iss == info->sendNext) {
                ASSERTLINE(249, info->iss == info->sendUna);
                flag |= TCP_FLAG_SYN;
                dataLen = 1;
            } else if (info->sendUna == info->iss) {
                offset = info->sendNext - info->sendUna - 1;
                break;
            }
        default:
            offset = info->sendNext - info->sendUna;
            break;
    }

    dataLen += info->sendLen;
    if (info->sendCallback && info->userSendLen > 0) {
        dataLen += info->userSendLen;
    }
    end = info->sendUna + dataLen;
    dataLen -= offset;

    if (hole) {
        ASSERTLINE(276, hole->rxmit == info->sendNext);
        dataLen = MIN(dataLen, hole->end - hole->rxmit);
    }

    switch (info->state) {
        case 5:
        case 8:
        case 9:
            if (0 <= dataLen && hole == NULL) {
                flag |= TCP_FLAG_FIN;
                dataLen++;
                end++;
            }
            break;
    }

    if (flag & TCP_FLAG_SYN) {
        flag &= ~TCP_FLAG_FIN;
        offset = 0;
        dataLen = 1;
        end = info->sendUna + dataLen;
    }

    if ((info->flag & 0x2000) && info->dupAcks >= TCP_RXMIT_THRESH) {
        win = info->sendWin;
    } else {
        win = MIN(info->sendWin, info->cWin);
    }

    if (win == 0 && SEQ_GT(end, info->sendUna) && info->rxmitAlarm.handler == NULL) {
        if (info->sendNext != info->sendUna) {
            info->sendNext = info->sendUna;
            info->rttTiming = FALSE;
            hole = NULL;
            info->dupAcks = 0;
            info->sendHoles = 0;
            info->sendFack = info->sendUna;
            info->rxmitData = 0;
            info->sendAwin = 0;
            info->sendRecover = info->sendMax;
            goto again;
        }
        flag |= TCP_FLAG_ACK;
        info->flag |= 0x200;
        win = 1;
    }

    useable = info->sendUna + win - info->sendNext;
    if ((info->flag & 0x2000) && !(info->flag & 0x1000) && dataLen > 0 && SEQ_GT(info->sendRecover, info->sendUna) && info->cWin <= info->sendAwin) {
        dataLen = 0;
    }

    sendSize = MIN(effSendMss, MIN(dataLen, useable));
    if (sendSize == dataLen && hole == NULL && sendSize > 0 && !(flag & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST))) {
        flag |= TCP_FLAG_PSH;
    }
    if ((flag & TCP_FLAG_FIN) && SEQ_GT(end, info->sendNext + sendSize)) {
        flag &= ~TCP_FLAG_FIN;
    }

    if (sendSize <= 0) {
        *pflag &= ~(TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_PSH);
        return 0;
    }

    *pflag = flag;
    *poffset = offset;
    return sendSize;
}

// Range: 0x6B8 -> 0x838
static s32 TCPPrepareData(TCPInfo* info /* r31 */, IFDatagram* datagram /* r27 */, s32 sendSize /* r1+0x10 */, s32 offset /* r29 */, u16 flag /* r25 */) {
    // Local variables
    s32 dataLen; // r30
    s32 len; // r28

    dataLen = sendSize;
    if (flag & TCP_FLAG_SYN) {
        dataLen--;
        ASSERTLINE(416, offset == 0);
    }
    if (flag & TCP_FLAG_FIN) {
        dataLen--;
    }

    if (dataLen > 0) {
        if (info->sendLen > 0 && offset < info->sendLen) {
            len = info->sendLen - offset;
            len = MIN(len, dataLen);
            datagram->nVec += IFRingGet(info->sendData, info->sendBuff, info->sendPtr + offset, info->sendLen - offset, &datagram->vec[1], len);
            dataLen -= len;
            offset += len;
        }

        if (dataLen > 0) {
            ASSERTLINE(438, info->sendCallback && 0 < info->userSendLen);
            offset -= info->sendLen;
            ASSERTLINE(440, offset + dataLen <= info->userSendLen);
            datagram->vec[datagram->nVec].data = info->userSendData + offset;
            datagram->vec[datagram->nVec].len = dataLen;
            datagram->nVec++;
        }
    }

    return dataLen;
}

// Range: 0x838 -> 0x96C
static BOOL DoSwsAvoidance(TCPInfo* info /* r3 */, s32 sendSize /* r4 */, s32 effSendMss /* r5 */, u16 flag /* r6 */) {
    // Local variables
    BOOL acked; // r31
    s32 win; // r30
    s32 reduction; // r29

    win = info->recvBuff - info->recvUser;
    reduction = win - info->recvWin;
    if (MIN(info->recvBuff / 2, effSendMss) <= reduction) {
        info->recvWin = win;
    }

    if (flag & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_ACK)) {
        return FALSE;
    }
    if (sendSize <= 0) {
        return TRUE;
    }
    if (effSendMss <= sendSize) {
        return FALSE;
    }

    if (info->flag & 0x2) {
        acked = (info->sendNext == info->sendUna);
    } else {
        acked = TRUE;
    }
    if (acked) {
        if (flag & TCP_FLAG_PSH) {
            return FALSE;
        }
        if (info->sendMaxWin / 2 <= sendSize) {
            return FALSE;
        }
    }

    if (SEQ_GT(info->sendMax, info->sendNext)) {
        return FALSE;
    }
    if (SEQ_GT(info->sendUp, info->sendUna)) {
        return FALSE;
    }
    if (info->flag & 0x1000) {
        return FALSE;
    }
    return TRUE;
}

// Range: 0x96C -> 0x9B8
static void DackHandler(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    TCPInfo* info; // r31

    info = (TCPInfo*)((u8*)alarm - offsetof(TCPInfo, dackAlarm));
    if (SEQ_GT(info->recvNext, info->recvAcked)) {
        TCPOutput(info, TCP_FLAG_ACK);
    }
}

// Range: 0x9B8 -> 0xA4C
static void TCPOutputCallback(TCPInfo* info /* r31 */, s32 result /* r29 */) {
    ASSERTLINE(568, info->datagram.interface == NULL);
    ASSERTLINE(569, info->datagram.queue == NULL);
    info->sendBusy = FALSE;
    if (result < 0) {
        info->err = result;
    }
    TCPOutput(info, 0);
}

// Range: 0xA4C -> 0x11D8
void TCPOutput(TCPInfo* info /* r31 */, u16 flag /* r1+0xC */) {
    // Local variables
    IPHeader* ip; // r28
    TCPHeader* tcp; // r30
    int optlen; // r23
    s32 sendSize; // r26
    s32 result; // r20
    IFVec* vec; // r22
    TCPSackHole* hole; // r25
    s32 onxt; // r21
    IFDatagram* datagram; // r29
    u8 header[60]; // r1+0x14
    s32 offset; // r1+0x10
    IPInterface* interface; // r24
    s32 win; // r19
    s32 reduction; // r18

    // References
    // -> struct TCPStatistics TCPStat;
    // -> struct IPInterface __IFDefault;

    hole = NULL;
    interface = NULL;
    if (info->state == 0) {
        return;
    }

    onxt = info->sendNext;
    if ((info->flag & 0x2000) && info->dupAcks >= TCP_RXMIT_THRESH) {
        hole = TCPSackOutput(info);
        if (hole) {
            info->sendNext = hole->rxmit;
        }
    }

    switch (info->state) {
        case 2:
            flag &= ~TCP_FLAG_ACK;
            break;
        case 3:
            if (SEQ_GT(info->irs + 1, info->recvAcked)) {
                flag |= TCP_FLAG_ACK;
            }
            break;
        default:
            win = info->recvBuff - info->recvUser;
            reduction = win - info->recvWin;
            if (MIN(2 * info->mss, info->sendMaxWin / 2) <= reduction) {
                flag |= TCP_FLAG_ACK;
            }
            break;
    }

    switch (info->state) {
        case 2:
        case 3:
            if (info->iss == info->sendNext) {
                flag |= TCP_FLAG_SYN;
            }
            break;
    }

    if (info->sendUna == info->sendMax && info->lastSend + info->rto < OSGetTime()) {
        info->cWin = 2 * info->mss;
    }

    tcp = (TCPHeader*)header;
    tcp->flag = 0;
    optlen = TCPMakeOption(tcp, info, flag);
    sendSize = TCPCalcSendSize(info, info->mss - optlen, &flag, &offset, hole);
    if (hole && info->sendNext != hole->rxmit) {
        onxt = info->sendNext;
        hole = NULL;
        info->flag &= ~0x1000;
    }

    if (DoSwsAvoidance(info, sendSize, info->mss - optlen, flag)) {
        if (sendSize > 0) {
            TCPStartRxmitTimer(info);
        }
        if (SEQ_GT(info->recvNext, info->recvAcked)) {
            OSCancelAlarm(&info->dackAlarm);
            OSSetAlarm(&info->dackAlarm, OSMillisecondsToTicks((OSTime)200), DackHandler);
        }
        return;
    }

    if (!info->sendBusy) {
        datagram = &info->datagram;
        IFInitDatagram(datagram, ETH_IP, 1);
        ip = (IPHeader*)info->header;
        datagram->callback = (void (*)(void*, s32))TCPOutputCallback;
        datagram->param = info;
    } else {
        interface = &__IFDefault;
        datagram = interface->alloc(interface, sizeof(IFDatagram) + 3 * sizeof(IFVec) + IP_MIN_HLEN + TCP_MIN_HLEN + optlen);
        if (datagram == NULL) {
            interface->stat.outDiscards++;
            return;
        }
        IFInitDatagram(datagram, ETH_IP, 4);
        datagram->nVec = 1;
        ip = (IPHeader*)&datagram->vec[4];
        memcpy(ip, info->header, IP_HLEN((IPHeader*)info->header));
    }

    if (sendSize > 0) {
        TCPPrepareData(info, datagram, sendSize, offset, flag);
    }

    ip->len = IP_HLEN(ip);
    OSCancelAlarm(&info->dackAlarm);
    if (info->state != 2) {
        flag |= TCP_FLAG_ACK;
    }
    ASSERTLINE(740, flag & TCP_FLAG_793);

    tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
    tcp->flag = ((TCPHeader*)header)->flag;
    memcpy(tcp + 1, header + TCP_MIN_HLEN, optlen);
    if (info->state != 3) {
        tcp->ack = info->recvAcked = info->recvNext;
    } else {
        tcp->ack = info->recvAcked = info->irs + 1;
    }
    tcp->src = info->pair.local.port;
    tcp->dst = info->pair.remote.port;
    if (sendSize > 0) {
        tcp->seq = info->sendNext;
    } else {
        tcp->seq = info->sendMax;
    }

    if (SEQ_GT(info->sendUp, tcp->seq)) {
        flag |= TCP_FLAG_URG;
        offset = info->sendUp - tcp->seq;
        tcp->urg = (u16)((65535 - IP_MIN_HLEN - TCP_MIN_HLEN < offset) ? 65535 : offset);
    } else {
        tcp->urg = 0;
        info->sendUp = info->sendUna;
    }

    if (info->state != 2) {
        flag |= TCP_FLAG_ACK;
    }
    tcp->flag &= ~TCP_FLAG_793;
    tcp->flag |= flag & TCP_FLAG_793;
    tcp->win = (u16)info->recvWin;
    tcp->sum = 0;

    ip->len += TCP_HLEN(tcp);
    for (vec = &datagram->vec[1]; vec < &datagram->vec[datagram->nVec]; vec++) {
        ip->len += (u16)vec->len;
    }
    ASSERTLINE(789, IP_MIN_HLEN + TCP_HLEN(tcp) <= ip->len);
    ASSERTLINE(790, IP_HLEN(ip) + TCP_HLEN(tcp) <= ip->len);

    info->sendNext += sendSize;
    if (SEQ_GT(info->sendNext, info->sendMax)) {
        info->sendMax = info->sendNext;
        if (!info->rttTiming) {
            info->rttTiming = TRUE;
            info->rttSeq = tcp->seq;
            info->rtt = OSGetTime();
        }
    } else if (sendSize > 0) {
        TCPStat.rxmitPackets++;
        TCPStat.rxmitBytes += ip->len - (IP_HLEN(ip) + TCP_HLEN(tcp));
    }

    if (info->sendNext != info->sendUna) {
        TCPStartRxmitTimer(info);
    }

    datagram->vec[0].data = ip;
    datagram->vec[0].len = IP_HLEN(ip) + TCP_HLEN(tcp);
    if (!info->sendBusy) {
        info->sendBusy = TRUE;
    } else {
        datagram->nVec = 4;
    }

    if (hole) {
        hole->rxmit += sendSize;
        info->rxmitData += sendSize;
        if (SEQ_GT(onxt, info->sendNext)) {
            info->sendNext = onxt;
        }
    }
    info->sendAwin = info->rxmitData + (info->sendNext - info->sendFack);
    info->flag &= ~0x1000;

    result = IPOut(datagram);
    if (result < 0) {
        if (interface) {
            ASSERTLINE(874, datagram->callback == NULL);
            interface->free(interface, datagram, sizeof(IFDatagram) + 3 * sizeof(IFVec) + IP_MIN_HLEN + TCP_MIN_HLEN + optlen);
        } else {
            ASSERTLINE(880, datagram->callback);
            TCPOutputCallback(info, result);
        }
        return;
    }

    info->lastSend = OSGetTime();
    TCPStat.sendTotal++;
}

// Range: 0x11D8 -> 0x1274
s32 __TCPCalcSendSize(TCPInfo* info /* r31 */, s32 effSendMss /* r1+0xC */, u16* pflag /* r29 */) {
    // Local variables
    int size; // r30
    s32 offset; // r1+0x14

    IFInitDatagram(&info->datagram, ETH_IP, 1);
    size = TCPCalcSendSize(info, effSendMss, pflag, &offset, NULL);
    if (size > 0) {
        TCPPrepareData(info, &info->datagram, size, offset, *pflag);
    }
    if (info->datagram.nVec < 2) {
        info->vec[0].data = NULL;
        info->vec[0].len = 0;
    }
    return size;
}
