#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

#undef IFIsEmptyQueue
#define IFIsEmptyQueue(queue) ((queue)->next == NULL)

char* TCPStateNames[11] = {
    "Closed",
    "Listen",
    "Syn_Sent",
    "Syn_Received",
    "Established",
    "FinWait1",
    "FinWait2",
    "Close_Wait",
    "Closing",
    "Last_Ack",
    "Time_Wait",
}; // size: 0x2C, address: 0x64

TCPStatistics TCPStat; // size: 0x14, address: 0x0
IFQueue TCPInfoQueue; // size: 0x8, address: 0x0

static TCPInfo* DoListen(IPInterface* interface, TCPInfo* info, IPHeader* ip, TCPHeader* seg);
static TCPInfo* DoSynSent(IPInterface* interface, TCPInfo* info, IPHeader* ip, TCPHeader* seg);
static void DoData(IPInterface* interface, TCPInfo* info, IPHeader* ip, TCPHeader* tcp, u16 flag);

// Range: 0x0 -> 0x8
static u32 Rotate(u32 n /* r3 */, u32 s /* r4 */) {
    return (n << s) | (n >> (32 - s));
}

// Range: 0x8 -> 0xDC
s32 TCPIsn(IPInfo* info /* r30 */) {
    // Local variables
    u32 m; // r31
    u32 unused; // Assumed, required for stack in release

    m = *__OSSystemTime;
    m = Rotate(m, m % 32);
    if (info) {
        m ^= IPU32(info->local.addr);
        m = Rotate(m, m % 32);
        m ^= Rotate(info->local.port, info->remote.port & 31);
        m ^= IPU32(info->remote.addr);
        m = Rotate(m, m % 32);
        m ^= Rotate(info->remote.port, info->local.port & 31);
    }
    m += (u32)(OSGetTime() / (OSTime)(OS_TIMER_CLOCK / 250000));
    return m;
}

// Range: 0xDC -> 0x258
u16 TCPCheckSum(IFVec* vec /* r29 */, s32 nVec /* r23 */) {
    // Local variables
    IPHeader* ip; // r30
    s32 hlen; // r24
    u16* p; // r27
    s32 len; // r28
    u32 sum; // r31
    u32 odd; // r25

    sum = 0;
    ASSERTLINE(263, 0 < nVec);
    ASSERTLINE(264, IP_MIN_HLEN + TCP_MIN_HLEN <= vec->len);
    ip = (IPHeader*)vec->data;
    ASSERTLINE(268, ip->proto == IP_PROTO_TCP);
    hlen = IP_HLEN(ip);

    sum += ((u16*)ip->src)[0];
    sum += ((u16*)ip->src)[1];
    sum += ((u16*)ip->dst)[0];
    sum += ((u16*)ip->dst)[1];
    sum += IP_PROTO_TCP;
    sum += ip->len - hlen;

    p = (u16*)((u8*)ip + hlen);
    len = vec->len - hlen;
    for (;;) {
        while (1 < len) {
            sum += *p++;
            len -= 2;
        }
        if (len == 1) {
            odd = *(u8*)p << 8;
        } else {
            odd = 0;
        }
        do {
            if (--nVec <= 0) {
                sum += odd;
                goto done;
            }
            vec++;
        } while (vec->len == 0);
        p = (u16*)vec->data;
        if (len == 1) {
            odd |= *(u8*)p;
            sum += odd;
            ((u8*)p)++;
            len = vec->len - 1;
        } else {
            len = vec->len;
        }
    }
done:
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return sum ^ 0xFFFF;
}

// Range: 0x258 -> 0x560
void TCPDumpHeader(const IPHeader* ip /* r29 */, const TCPHeader* tcp /* r31 */) {
    // Local variables
    int optlen; // r25
    u8* opt; // r28
    int len; // r30
    s32* edge; // r26
    int edgelen; // r24

    OSReport("TCP: %d.%d.%d.%d:%d > %d.%d.%d.%d:%d ", ip->src[0], ip->src[1], ip->src[2], ip->src[3], tcp->src, ip->dst[0], ip->dst[1], ip->dst[2], ip->dst[3], tcp->dst);
    if (tcp->flag & TCP_FLAG_SYN) {
        OSReport("S");
    }
    if (tcp->flag & TCP_FLAG_FIN) {
        OSReport("F");
    }
    if (tcp->flag & TCP_FLAG_RST) {
        OSReport("R");
    }
    if (tcp->flag & TCP_FLAG_PSH) {
        OSReport("P");
    }
    if ((tcp->flag & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_PSH)) == 0) {
        OSReport(".");
    }
    len = ip->len - IP_HLEN(ip) - TCP_HLEN(tcp);
    OSReport(" %u:%u(%d) ", tcp->seq, tcp->seq + len, len);
    if (tcp->flag & TCP_FLAG_ACK) {
        OSReport("ack %u ", tcp->ack);
    }
    OSReport("win %u ", tcp->win);
    if (tcp->flag & TCP_FLAG_URG) {
        OSReport("urg %u ", tcp->urg);
    }
    ASSERTLINE(357, 0 <= ip->len - IP_HLEN(ip) - TCP_HLEN(tcp));

    for (optlen = TCP_HLEN(tcp) - TCP_MIN_HLEN, opt = (u8*)(tcp + 1); 0 < optlen && *opt != TCP_OPT_EOL; opt += len, optlen -= len) {
        if (*opt == TCP_OPT_NOP) {
            len = 1;
        } else {
            len = opt[1];
            if (len < 2) {
                break;
            }
        }
        switch (*opt) {
            case TCP_OPT_NOP:
                OSReport("<nop> ");
                break;
            case TCP_OPT_EOL:
                OSReport("<eol> ");
                break;
            case TCP_OPT_MSS:
                if (len == 4) {
                    OSReport("<mss: %d> ", *(u16*)(opt + 2));
                }
                break;
            case TCP_OPT_SACK_PERMITTED:
                if (len == 2) {
                    OSReport("<sack-permitted> ", *(u16*)(opt + 2));
                }
                break;
            case TCP_OPT_SACK:
                if (2 < len && ((len - 2) & 7) == 0) {
                    edge = (s32*)(opt + 2);
                    edgelen = len - 2;
                    OSReport("<sack:");
                    while (0 < edgelen) {
                        OSReport(" %u", edge[0]);
                        OSReport("-%u", edge[1]);
                        edge += 2;
                        edgelen -= 8;
                    }
                    OSReport("> ");
                }
                break;
            case TCP_OPT_WS:
            default:
                OSReport("<opt: [%d]> ", *opt);
                break;
        }
    }
    OSReport("\n");
}

// Range: 0x560 -> 0x694
static int DoOption(TCPInfo* info /* r29 */, IPHeader*, TCPHeader* tcp /* r28 */) {
    // Local variables
    int optlen; // r27
    u8* opt; // r31
    int len; // r30
    u16 mss; // r26

    for (optlen = TCP_HLEN(tcp) - TCP_MIN_HLEN, opt = (u8*)(tcp + 1); 0 < optlen && *opt != TCP_OPT_EOL; opt += len, optlen -= len) {
        if (*opt == TCP_OPT_NOP) {
            len = 1;
        } else {
            len = opt[1];
            if (len < 2) {
                break;
            }
        }
        switch (*opt) {
            case TCP_OPT_MSS:
                if (len == 4 && (tcp->flag & TCP_FLAG_SYN)) {
                    mss = *(u16*)(opt + 2);
                    info->mss = MIN(mss, info->mss);
                    info->cWin = 2 * info->mss;
                    info->ssThresh = 65535;
                }
                break;
            case TCP_OPT_SACK_PERMITTED:
                if (len == 2 && (tcp->flag & TCP_FLAG_SYN)) {
                    info->flag |= 0x2000;
                }
                break;
            case TCP_OPT_SACK:
                TCPUpdateScoreboard(info, tcp, opt, len);
                break;
        }
    }
    return TRUE;
}

// Range: 0x694 -> 0x6E8
s32 TCPGetSegmentLength(IPHeader* ip /* r3 */, TCPHeader* tcp /* r4 */) {
    // Local variables
    s32 len; // r31

    len = ip->len - IP_HLEN(ip) - TCP_HLEN(tcp);
    if (tcp->flag & TCP_FLAG_SYN) {
        len++;
    }
    if (tcp->flag & TCP_FLAG_FIN) {
        len++;
    }
    return len;
}

// Range: 0x6E8 -> 0x944
void TCPRespond(IPInterface* interface /* r25 */, TCPInfo* info /* r27 */, u8* dstAddr /* r1+0x10 */, u16 dst /* r1+0x14 */, u8* srcAddr /* r1+0x18 */, u16 src /* r1+0x1C */, s32 seq /* r1+0x20 */, s32 ack /* r1+0x24 */, u16 flag /* r22 */, u16 win /* r1+0x5E */) {
    // Local variables
    IPHeader* ip; // r31
    TCPHeader* tcp; // r30
    IFDatagram* datagram; // r28
    s32 len; // r23
    s32 optlen; // r29
    IFBlock* block; // r26

    optlen = 0;
    if (info && (info->flag & 0x2000) && info->asb[0].ptr != NULL) {
        ASSERTLINE(535, !(flag & TCP_FLAG_SYN));
        optlen += 2;
        for (block = &info->asb[3]; info->asb <= block; block--) {
            if (block->ptr != NULL) {
                break;
            }
        }
        optlen += (block + 1 - info->asb) * 8;
        optlen = (optlen + 3) & ~3;
        ASSERTLINE(547, optlen % 4 == 0);
        ASSERTLINE(548, TCP_MIN_HLEN + optlen <= TCP_MAX_HLEN);
    } else {
        info = NULL;
    }

    len = sizeof(IFDatagram) + sizeof(IPHeader) + sizeof(TCPHeader) + optlen;
    datagram = interface->alloc(interface, len);
    if (datagram != NULL) {
        IFInitDatagram(datagram, ETH_IP, 1);
        ip = (IPHeader*)(datagram + 1);
        memmove(ip->dst, dstAddr, IP_ALEN);
        memmove(ip->src, srcAddr, IP_ALEN);
        ip->verlen = 0x45;
        ip->tos = 0;
        ip->len = IP_HLEN(ip) + TCP_MIN_HLEN + optlen;
        ip->ttl = 255;
        ip->proto = IP_PROTO_TCP;
        ip->frag = 0;

        tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
        tcp->flag = flag & 0x3F;
        TCPMakeOption(tcp, info, flag);
        tcp->src = src;
        tcp->dst = dst;
        tcp->seq = seq;
        tcp->ack = ack;
        tcp->win = win;
        tcp->sum = 0;
        tcp->urg = 0;

        datagram->vec[0].data = ip;
        datagram->vec[0].len = ip->len;
        if (IPOut(datagram) < 0) {
            interface->free(interface, datagram, len);
        }
    }
}

// Range: 0x944 -> 0x9E4
static void DoReset(IPInterface* interface /* r1+0x10 */, IPHeader* ip /* r27 */, TCPHeader* tcp /* r30 */) {
    // Local variables
    u16 flag; // r31
    s32 seq; // r29
    s32 ack; // r28

    flag = tcp->flag;
    if (!(flag & TCP_FLAG_RST)) {
        if (!(flag & TCP_FLAG_ACK)) {
            seq = 0;
            ack = tcp->seq + TCPGetSegmentLength(ip, tcp);
            flag = TCP_FLAG_RST | TCP_FLAG_ACK;
        } else {
            seq = tcp->ack;
            ack = 0;
            flag = TCP_FLAG_RST;
        }
        TCPRespond(interface, NULL, ip->src, tcp->src, ip->dst, tcp->dst, seq, ack, flag, 0);
    }
}

// Range: 0x9E4 -> 0xA5C
static void DoAck(IPInterface* interface /* r1+0x10 */, TCPInfo* info /* r31 */, IPHeader* ip /* r29 */, TCPHeader* tcp /* r30 */) {
    if (!(tcp->flag & TCP_FLAG_RST)) {
        TCPRespond(interface, info, ip->src, tcp->src, ip->dst, tcp->dst, info->sendUna, info->recvNext, TCP_FLAG_ACK, info->recvWin);
    }
}

// Range: 0xA5C -> 0xD44
static int TCPTrimSegment(TCPInfo* info /* r31 */, TCPHeader* tcp /* r30 */, u16* flag /* r26 */) {
    // Local variables
    s32 drop; // r29
    int accept; // r27
    s32 end; // r25

    ASSERTLINE(654, flag);
    ASSERTLINE(655, TCP_STATE_SYN_RECEIVED <= info->state);

    *flag = 0;
    drop = info->recvNext - tcp->seq;
    if (0 < drop) {
        *flag |= TCP_FLAG_ACK;
        if (tcp->flag & TCP_FLAG_SYN) {
            tcp->flag &= ~TCP_FLAG_SYN;
            tcp->seq++;
            info->segLen--;
            if (1 < tcp->urg) {
                tcp->urg--;
            } else {
                tcp->flag &= ~TCP_FLAG_URG;
            }
            drop--;
        }
        if (info->segLen <= drop) {
            if (tcp->flag & TCP_FLAG_FIN) {
                tcp->flag &= ~TCP_FLAG_FIN;
            }
            drop = info->segLen;
        }
        if (0 < drop) {
            tcp->seq += drop;
            info->segLen -= drop;
            info->segBegin += drop;
            if (drop < tcp->urg) {
                tcp->urg -= (u16)drop;
            } else {
                tcp->flag &= ~TCP_FLAG_URG;
                tcp->urg = 0;
            }
        }
    }

    drop = (tcp->seq + info->segLen) - (info->recvNext + info->recvWin);
    if (0 < drop) {
        *flag |= TCP_FLAG_ACK;
        if (tcp->flag & TCP_FLAG_FIN) {
            tcp->flag &= ~TCP_FLAG_FIN;
            info->segLen--;
            drop--;
        }
        if (info->segLen < drop) {
            drop = info->segLen;
        }
        info->segLen -= drop;
    }

    if (info->recvWin == 0) {
        return tcp->seq == info->recvNext && info->segLen == 0;
    }

    ASSERTLINE(731, 0 < info->recvWin);
    accept = TCP_SEQ_GE(info->recvNext, tcp->seq) && TCP_SEQ_GT(tcp->seq, info->recvNext + info->recvWin);
    if (info->segLen == 0) {
        return accept;
    }

    ASSERTLINE(740, 0 < info->segLen);
    end = tcp->seq + info->segLen - 1;
    accept = TCP_SEQ_GE(info->recvNext, end) && TCP_SEQ_GT(end, info->recvNext + info->recvWin);
    return accept;
}

// Range: 0xD44 -> 0xDB8
static void TCPOpenWindow(TCPInfo* info /* r3 */, TCPHeader*) {
    if (info->dupAcks < 3) {
        if (info->cWin < info->ssThresh) {
            info->cWin += info->mss;
        } else {
            info->cWin += info->mss * info->mss / info->cWin;
        }
        if (65535 < info->cWin) {
            info->cWin = 65535;
        }
    }
}

// Range: 0xDB8 -> 0x17F4
void TCPIn(IPInterface* interface /* r28 */, IPHeader* ip /* r29 */, u32) {
    // Local variables
    TCPInfo* info; // r31
    TCPHeader* tcp; // r30
    IFVec vec; // r1+0x18
    s32 sent; // r27
    s32 sendLen; // r22
    int finacked; // r26
    TCPCallback callback; // r25
    u16 flag; // r1+0x14
    s32 len; // r23

    // References
    // -> struct TCPStatistics TCPStat;
    flag = 0;
    tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
    if (TCP_HLEN(tcp) < TCP_MIN_HLEN) {
        return;
    }
    if (ip->len < IP_HLEN(ip) + TCP_HLEN(tcp)) {
        return;
    }

    vec.data = ip;
    vec.len = ip->len;
    if (TCPCheckSum(&vec, 1) != 0) {
        return;
    }

    TCPStat.recvTotal++;
    info = TCPLookupInfo(ip, tcp);
    if ((info == NULL || info->state < TCP_STATE_ESTABLISHED) && TCPTestTimeWait(interface, ip, tcp)) {
        return;
    }
    if (info == NULL) {
        DoReset(interface, ip, tcp);
        return;
    }

    info->interface = interface;
    if (info->state == TCP_STATE_CLOSED) {
        return;
    }

    info->segLen = TCPGetSegmentLength(ip, tcp);
    info->segBegin = (u8*)tcp + TCP_HLEN(tcp);

    switch (info->state) {
        case TCP_STATE_LISTEN:
            info = DoListen(interface, info, ip, tcp);
            if (!info) {
                return;
            }
            TCPTrimSegment(info, tcp, &flag);
            if (tcp->flag & TCP_FLAG_FIN) {
                tcp->flag &= ~TCP_FLAG_FIN;
                info->segLen--;
            }
            DoData(interface, info, ip, tcp, 0);
            return;
        case TCP_STATE_SYN_SENT:
            if (!DoSynSent(interface, info, ip, tcp)) {
                return;
            }
            TCPTrimSegment(info, tcp, &flag);
            if (tcp->flag & TCP_FLAG_FIN) {
                tcp->flag &= ~TCP_FLAG_FIN;
                info->segLen--;
            }
            DoData(interface, info, ip, tcp, 0);
            return;
        case TCP_STATE_SYN_RECEIVED:
            if (tcp->flag & TCP_FLAG_ACK) {
                if (TCP_SEQ_GE(tcp->ack, info->sendUna) || TCP_SEQ_GT(info->sendMax, tcp->ack)) {
                    DoReset(interface, ip, tcp);
                    return;
                }
            }
            if (TCP_SEQ_GT(tcp->seq, info->irs)) {
                DoReset(interface, ip, tcp);
                return;
            }
            break;
    }

    if (tcp->flag & TCP_FLAG_RST) {
        if (TCP_SEQ_GE(info->recvNext, tcp->seq) && TCP_SEQ_GT(tcp->seq, info->recvNext + info->recvWin)) {
            switch (info->state) {
                case TCP_STATE_SYN_RECEIVED:
                    info->err = -11;
                    TCPAbort(info);
                    return;
                case TCP_STATE_ESTABLISHED:
                case TCP_STATE_FIN_WAIT1:
                case TCP_STATE_FIN_WAIT2:
                case TCP_STATE_CLOSE_WAIT:
                    info->err = -3;
                    TCPAbort(info);
                    return;
                case TCP_STATE_CLOSING:
                case TCP_STATE_LAST_ACK:
                    TCPAbort(info);
                    return;
                case TCP_STATE_TIME_WAIT:
                    return;
            }
        } else {
            return;
        }
    }

    if (!TCPTrimSegment(info, tcp, &flag)) {
        DoAck(interface, info, ip, tcp);
        return;
    }

    if (tcp->flag & TCP_FLAG_SYN) {
        info->err = -3;
        DoReset(interface, ip, tcp);
        TCPAbort(info);
        return;
    }

    if (!(tcp->flag & TCP_FLAG_ACK)) {
        return;
    }

    if (info->flag & 0x2000) {
        TCPDeleteSackHoles(info, tcp);
    }
    DoOption(info, ip, tcp);

    sent = tcp->ack - info->sendUna;
    switch (info->state) {
        case TCP_STATE_SYN_RECEIVED:
            if (info->sendUna == info->iss) {
                ASSERTLINE(1053, TCP_SEQ_GT(info->sendUna, tcp->ack));
                sent--;
            }
            info->sendWin = tcp->win;
            info->sendWL1 = tcp->seq;
            info->sendWL2 = tcp->ack;
            info->sendMaxWin = info->sendWin;
            info->state = TCP_STATE_ESTABLISHED;
            if (info->openCallback) {
                if (info->openResult) {
                    *info->openResult = 0;
                    info->openResult = NULL;
                }
                callback = info->openCallback;
                info->openCallback = NULL;
                callback(info, 0);
            }
            // fallthrough
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_FIN_WAIT1:
        case TCP_STATE_FIN_WAIT2:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            if (TCP_SEQ_GT(info->sendMax, tcp->ack)) {
                DoAck(interface, info, ip, tcp);
                return;
            }

            if (TCP_SEQ_GE(tcp->ack, info->sendUna)) {
                if (info->sendUna == info->sendMax) {
                    info->dupAcks = 0;
                } else if ((info->flag & 0x2000) && info->dupAcks < 3) {
                    if (info->sendUna != tcp->ack || tcp->win < info->sendWin) {
                        info->dupAcks = 0;
                    } else if (TCP_SEQ_GE(tcp->ack, info->sendRecover)) {
                        info->dupAcks = 0;
                    } else if (++info->dupAcks == 3 || info->mss * 3 < info->sendFack - info->sendUna) {
                        ASSERTLINE(1134, TCP_SEQ_GT(info->sendRecover, info->sendUna));
                        info->sendRecover = info->sendMax;
                        info->ssThresh = MIN(info->cWin, info->sendWin) / 2;
                        info->ssThresh = MAX(info->ssThresh, 2 * info->mss);
                        info->rttTiming = FALSE;
                        OSCancelAlarm(&info->rxmitAlarm);
                        info->dupAcks = 3;
                        info->flag |= 0x1000;
                        info->cWin = info->ssThresh;
                    }
                }
                break;
            }

            ASSERTLINE(1162, TCP_SEQ_GT(info->sendUna, tcp->ack));
            if ((info->flag & 0x2000) && 3 <= info->dupAcks) {
                if (TCP_SEQ_GT(tcp->ack, info->sendRecover)) {
                    if (info->dupAcks++ == 3) {
                        OSCancelAlarm(&info->rxmitAlarm);
                        info->rttTiming = FALSE;
                    }
                } else {
                    info->cWin = MIN(info->ssThresh, info->sendAwin + info->mss);
                    info->cWin = MAX(info->mss, info->cWin);
                    info->dupAcks = 0;
                    info->rttTiming = FALSE;
                }
            } else {
                OSCancelAlarm(&info->rxmitAlarm);
            }

            TCPOpenWindow(info, tcp);
            info->sendUna = tcp->ack;
            if (TCP_SEQ_GT(info->sendNext, info->sendUna)) {
                info->sendNext = info->sendUna;
            }
            if (TCP_SEQ_GT(info->sendFack, info->sendUna)) {
                info->sendFack = info->sendUna;
                info->sendAwin = info->rxmitData + (info->sendNext - info->sendFack);
            }

            sendLen = info->sendLen;
            if (info->sendCallback && 0 < info->userSendLen) {
                sendLen += info->userSendLen;
            }
            if (sendLen < sent) {
                ASSERTLINE(1227, TCP_SEQ_GE(info->sendMax, tcp->ack));
                sent--;
                finacked = TRUE;
            } else {
                finacked = FALSE;
            }

            if (0 < sent && 0 < info->sendLen) {
                len = MIN(sent, info->sendLen);
                info->sendPtr = IFRingPut(info->sendData, info->sendBuff, info->sendPtr, info->sendLen, len);
                info->sendLen -= len;
                sent -= len;
            }
            if (0 < sent && info->sendCallback && 0 < info->userSendLen) {
                info->userSendData += sent;
                info->userSendLen -= sent;
                info->userAcked += sent;
            }

            TCPSendIn(info, FALSE);
            if (0 < info->pair.poll) {
                __IPWakeupPollingThreads();
            }

            callback = info->sendCallback;
            if (callback && info->userSendLen <= 0) {
                if (info->sendResult) {
                    *info->sendResult = info->userAcked;
                    info->sendResult = NULL;
                }
                info->sendCallback = NULL;
                callback(info, info->userAcked);
            }

            switch (info->state) {
                case TCP_STATE_FIN_WAIT1:
                    if (finacked) {
                        info->state = TCP_STATE_FIN_WAIT2;
                    }
                    break;
                case TCP_STATE_CLOSING:
                    if (finacked) {
                        info->err = 0;
                        TCPStartTimeWait(interface, info);
                        return;
                    }
                    break;
                case TCP_STATE_LAST_ACK:
                    if (finacked) {
                        info->err = 0;
                        TCPAbort(info);
                        return;
                    }
                    break;
            }
            break;
    }

    if (info->rttTiming && TCP_SEQ_GT(info->rttSeq, tcp->ack)) {
        info->rttTiming = FALSE;
        TCPUpdateRtt(info, OSGetTime() - info->rtt);
    }

    if (TCP_SEQ_GT(info->sendWL1, tcp->seq) || (info->sendWL1 == tcp->seq && TCP_SEQ_GE(info->sendWL2, tcp->ack)) || (info->sendWL2 == tcp->ack && info->sendWin < tcp->win)) {
        info->sendWin = tcp->win;
        info->sendWL1 = tcp->seq;
        info->sendWL2 = tcp->ack;
        if (info->sendMaxWin < info->sendWin) {
            info->sendMaxWin = info->sendWin;
        }
    }

    TCPStopRxmitTimer(info, tcp);
    DoData(interface, info, ip, tcp, flag);
}

// Range: 0x17F4 -> 0x1C08
static TCPInfo* DoListen(IPInterface* interface /* r22 */, TCPInfo* info /* r30 */, IPHeader* ip /* r28 */, TCPHeader* seg /* r29 */) {
    // Local variables
    IPHeader* header; // r24
    TCPInfo* accepted; // r31
    int accept; // r23
    IFQueue* ___next; // r27
    IFQueue* ___prev; // r26

    // References
    // -> struct IFQueue TCPInfoQueue;
    ASSERTLINE(1364, seg->dst == info->pair.local.port);

    if (IPIsBroadcastAddr(info->interface, ip->src) || IP_CLASSD(ip->src)) {
        return NULL;
    }
    if (seg->flag & TCP_FLAG_RST) {
        return NULL;
    }
    if (seg->flag & TCP_FLAG_ACK) {
        DoReset(info->interface, ip, seg);
        return NULL;
    }
    if (!(seg->flag & TCP_FLAG_SYN)) {
        return NULL;
    }

    if (info->local) {
        memmove(info->local->addr, ip->dst, IP_ALEN);
        info->local->port = seg->dst;
    }
    if (info->remote) {
        memmove(info->remote->addr, ip->src, IP_ALEN);
        info->remote->port = seg->src;
    }

    if (info->openCallback) {
        if (info->openResult) {
            *info->openResult = 0;
        }
        accept = ((int (*)(TCPInfo*, s32))info->openCallback)(info, 0);
        if (!accept) {
            return NULL;
        }
    }

    if (info->queueListen.next == NULL) {
        return NULL;
    }

    accepted = (TCPInfo*)info->queueListen.next;
    ___next = accepted->linkListen.next;
    if (___next == NULL) {
        info->queueListen.prev = NULL;
    } else {
        ((TCPInfo*)___next)->linkListen.prev = NULL;
    }
    info->queueListen.next = ___next;

    ASSERTLINE(1424, accepted->listening == info);
    accepted->listening = NULL;
    accepted->interface = interface;
    accepted->err = 0;
    TCPInitRtt(accepted);
    accepted->flag &= ~0x30082;
    accepted->flag |= info->flag & 0x30082;
    accepted->flag |= 0x100;
    accepted->linger = info->linger;

    accepted->sendPtr = accepted->sendData;
    accepted->sendLen = 0;
    accepted->recvPtr = accepted->recvData;
    accepted->recvWin = accepted->recvBuff;
    accepted->recvUser = 0;
    ASSERTLINE(1440, IFIsEmptyQueue(&accepted->queueListen));
    accepted->userSendData = NULL;
    accepted->userSendLen = 0;
    accepted->userData = NULL;
    accepted->userBuff = 0;
    accepted->userLen = 0;

    memmove(accepted->pair.remote.addr, ip->src, IP_ALEN);
    memmove(accepted->pair.local.addr, ip->dst, IP_ALEN);
    accepted->pair.remote.port = seg->src;
    accepted->pair.local.port = seg->dst;

    header = (IPHeader*)accepted->header;
    memmove(header->dst, ip->src, IP_ALEN);
    memmove(header->src, ip->dst, IP_ALEN);

    accepted->mss = interface->mtu - 40;
    accepted->cWin = 2 * accepted->mss;
    accepted->ssThresh = 65535;

    accepted->iss = TCPIsn(&accepted->pair);
    accepted->irs = seg->seq;
    accepted->recvAcked = accepted->irs;
    accepted->recvNext = seg->seq + 1;
    accepted->recvUp = info->recvNext;
    accepted->sendUna = accepted->iss;
    accepted->sendNext = accepted->iss;
    accepted->sendMax = accepted->iss;
    accepted->sendUp = accepted->iss;
    accepted->segLen = info->segLen;
    accepted->segBegin = info->segBegin;
    info->segLen = 0;
    info->segBegin = NULL;
    accepted->sendRecover = accepted->sendUna;
    accepted->sendFack = accepted->sendUna;
    accepted->lastSack = accepted->sendUna;
    accepted->rxmitData = 0;
    accepted->sendAwin = 0;
    DoOption(accepted, ip, seg);
    accepted->state = TCP_STATE_SYN_RECEIVED;

    ___prev = TCPInfoQueue.prev;
    if (___prev == NULL) {
        TCPInfoQueue.next = (IFQueue*)accepted;
    } else {
        ((TCPInfo*)___prev)->pair.link.next = (IFQueue*)accepted;
    }
    accepted->pair.link.prev = ___prev;
    accepted->pair.link.next = NULL;
    TCPInfoQueue.prev = (IFQueue*)accepted;

    return accepted;
}

// Range: 0x1C08 -> 0x1E08
static TCPInfo* DoSynSent(IPInterface*, TCPInfo* info /* r31 */, IPHeader* ip /* r28 */, TCPHeader* seg /* r30 */) {
    // Local variables
    TCPCallback callback; // r29

    if (seg->flag & TCP_FLAG_ACK) {
        if (TCP_SEQ_GE(seg->ack, info->iss) || TCP_SEQ_GT(info->sendMax, seg->ack)) {
            DoReset(info->interface, ip, seg);
            return NULL;
        }
    }

    if (seg->flag & TCP_FLAG_RST) {
        if (seg->flag & TCP_FLAG_ACK) {
            info->err = -3;
            TCPAbort(info);
        }
        return NULL;
    }

    if (!(seg->flag & TCP_FLAG_SYN)) {
        return NULL;
    }

    info->recvNext = seg->seq + 1;
    info->recvUp = info->recvNext;
    info->irs = seg->seq;
    info->recvAcked = info->irs;
    DoOption(info, ip, seg);

    if (seg->flag & TCP_FLAG_ACK) {
        if (info->rttTiming && TCP_SEQ_GT(info->rttSeq, seg->ack)) {
            info->rttTiming = FALSE;
            TCPUpdateRtt(info, OSGetTime() - info->rtt);
        }
        info->sendWin = seg->win;
        info->sendWL1 = seg->seq;
        info->sendWL2 = seg->ack;
        info->sendMaxWin = info->sendWin;
        if (info->sendUna == info->iss) {
            info->sendUna++;
            if (TCP_SEQ_GT(info->sendNext, info->sendUna)) {
                info->sendNext = info->sendUna;
            }
        }
        TCPStopRxmitTimer(info, seg);
        info->state = TCP_STATE_ESTABLISHED;
        if (info->openCallback) {
            if (info->openResult) {
                *info->openResult = 0;
                info->openResult = NULL;
            }
            callback = info->openCallback;
            info->openCallback = NULL;
            callback(info, 0);
        }
        return info;
    }

    info->state = TCP_STATE_SYN_RECEIVED;
    return info;
}

// Range: 0x1E08 -> 0x1F28
static void DoUrg(TCPInfo* info /* r31 */, TCPHeader* tcp /* r30 */) {
    // Local variables
    s32 up; // r29

    ASSERTLINE(1615, (tcp->flag & TCP_FLAG_SYN) == 0);
    if ((tcp->flag & TCP_FLAG_URG) && tcp->urg != 0) {
        switch (info->state) {
            case TCP_STATE_ESTABLISHED:
            case TCP_STATE_FIN_WAIT1:
            case TCP_STATE_FIN_WAIT2:
                up = tcp->seq + tcp->urg;
                up = TCP_SEQ_GT(info->recvUp, up) ? up : info->recvUp;
                info->recvUp = up;
                info->flag &= ~0x60;
                if (tcp->urg <= info->segLen) {
                    info->oob = info->segBegin[tcp->urg - 1];
                    info->flag |= 0x20;
                }
                info->recvUrg = info->userLen + info->recvUser + (info->recvUp - info->recvNext);
                break;
            case TCP_STATE_CLOSE_WAIT:
            case TCP_STATE_CLOSING:
            case TCP_STATE_LAST_ACK:
            case TCP_STATE_TIME_WAIT:
                break;
        }
    } else {
        if (TCP_SEQ_GT(info->recvUp, info->recvNext)) {
            info->recvUp = info->recvNext;
        }
    }
}

// Range: 0x1F28 -> 0x23F4
static void DoData(IPInterface* interface /* r1+0x10 */, TCPInfo* info /* r31 */, IPHeader* ip /* r1+0x18 */, TCPHeader* tcp /* r30 */, u16 flag /* r26 */) {
    // Local variables
    TCPCallback callback; // r27
    s32 result; // r29
    s32 adv; // r1+0x28
    BOOL urgent; // r1+0x24

    ASSERTLINE(1659, (tcp->flag & TCP_FLAG_SYN) == 0);
    info->err = 0;
    DoUrg(info, tcp);

    switch (info->state) {
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_ESTABLISHED:
            if (info->closeCallback || (info->flag & 0x8)) {
                info->state = TCP_STATE_FIN_WAIT1;
            }
            // fallthrough
        case TCP_STATE_FIN_WAIT1:
        case TCP_STATE_FIN_WAIT2:
            adv = info->segLen;
            ASSERTLINE(1683, !(tcp->flag & TCP_FLAG_SYN));
            if (tcp->flag & TCP_FLAG_FIN) {
                adv--;
            }
            if ((info->flag & 0x11) && 0 < adv) {
                info->err = -8;
                DoReset(interface, ip, tcp);
                TCPAbort(info);
                return;
            }

            if (info->recvNext == tcp->seq) {
                if (0 < adv) {
                    if ((tcp->flag & TCP_FLAG_PSH) || info->dackAlarm.handler != NULL || info->recvWin == 0) {
                        flag |= TCP_FLAG_ACK;
                    }
                    info->recvPtr = IFRingInEx(info->recvData, info->recvBuff, info->recvPtr, info->recvUser, 0, info->segBegin, &adv, info->asb, 4);
                    info->recvUser += adv;
                    info->segBegin += adv;
                    info->recvNext += adv;
                    info->recvWin -= adv;
                    if (0 < info->pair.poll) {
                        __IPWakeupPollingThreads();
                    }
                }
            } else {
                ASSERTLINE(1743, TCP_SEQ_GT(info->recvNext, tcp->seq));
                if (0 < adv) {
                    flag |= TCP_FLAG_ACK;
                }
                info->recvPtr = IFRingInEx(info->recvData, info->recvBuff, info->recvPtr, info->recvUser, tcp->seq - info->recvNext, info->segBegin, &adv, info->asb, 4);
                ASSERTLINE(1759, adv == 0);
                if (tcp->flag & TCP_FLAG_FIN) {
                    tcp->flag &= ~TCP_FLAG_FIN;
                    info->segLen--;
                }
            }
            break;
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_TIME_WAIT:
            break;
    }

    if (tcp->flag & TCP_FLAG_FIN) {
        info->recvNext++;
        flag |= TCP_FLAG_ACK;
        switch (info->state) {
            case TCP_STATE_SYN_RECEIVED:
                ASSERTLINE(1787, info->openCallback == NULL);
                // fallthrough
            case TCP_STATE_ESTABLISHED:
                info->state = TCP_STATE_CLOSE_WAIT;
                break;
            case TCP_STATE_FIN_WAIT1:
                info->state = TCP_STATE_CLOSING;
                break;
            case TCP_STATE_FIN_WAIT2:
                info->state = TCP_STATE_TIME_WAIT;
                break;
        }
    }

    if (info->recvCallback) {
        result = TCPRecvOut(info, &urgent);
        if (info->recvLowat <= result || (tcp->flag & TCP_FLAG_FIN) || (0 < result && urgent)) {
            callback = info->recvCallback;
            if (info->recvResult) {
                *info->recvResult = result;
                info->recvResult = NULL;
            }
            info->recvCallback = NULL;
            info->userData = NULL;
            info->userLen = 0;
            callback(info, result);
        }
    }

    if (0 < info->recvUrg && (0 < info->recvUrg || (info->flag & 0x20)) && info->urgCallback && !(info->flag & 0x40)) {
        if (info->flag & 0x20) {
            result = TRUE;
            if (!(info->flag & 0x800)) {
                info->flag ^= 0x60;
            }
        } else {
            result = FALSE;
        }
        if (info->urgResult) {
            *info->urgResult = result;
            info->urgResult = NULL;
        }
        if (info->urgData) {
            *info->urgData = info->oob;
            info->urgData = NULL;
        }
        callback = info->urgCallback;
        info->urgCallback = NULL;
        callback(info, result);
    }

    if ((tcp->flag & TCP_FLAG_FIN) && info->state == TCP_STATE_TIME_WAIT) {
        TCPStartTimeWait(info->interface, info);
        return;
    }
    TCPOutput(info, flag);
}

// Range: 0x23F4 -> 0x2524
s32 TCPSendIn(TCPInfo* info /* r31 */, BOOL nonblock /* r28 */) {
    // Local variables
    s32 useable; // r29
    s32 len; // r30

    if (info->sendCallback == NULL || info->userSendLen <= 0) {
        return 0;
    }

    if (!nonblock && info->sendLen == 0 && info->sendBuff < info->userSendLen) {
        len = 0;
    } else {
        useable = info->sendBuff - info->sendLen;
        len = MIN(useable, info->userSendLen);
        if (nonblock && len < info->sendLowat) {
            return 0;
        }
    }

    if (0 < len) {
        info->sendPtr = IFRingIn(info->sendData, info->sendBuff, info->sendPtr, info->sendLen, info->userSendData, len);
        info->sendLen += len;
        info->userSendData += len;
        info->userSendLen -= len;
        info->userAcked += len;
    }

    if (nonblock) {
        info->userSendData = NULL;
        info->userSendLen = 0;
    }
    return len;
}

// Range: 0x2524 -> 0x2688
s32 TCPPeekOut(TCPInfo* info /* r31 */, void* ptr /* r1+0xC */, s32 len /* r30 */, BOOL peek /* r1+0x14 */, BOOL* urgent /* r29 */) {
    // Local variables
    void* nextPtr; // r28
    u8 oob; // r1+0x1C

    *urgent = FALSE;
    len = MIN(len, info->recvUser);
    if (len <= 0) {
        return 0;
    }

    if (0 < info->recvUrg) {
        if (info->recvUrg == 1) {
            if (info->flag & 0x80) {
                info->recvPtr = IFRingOut(info->recvData, info->recvBuff, info->recvPtr, info->recvUser, &oob, 1);
                info->recvUser--;
                info->recvUrg--;
                len = MIN(len, info->recvUser);
            } else {
                len = 1;
                *urgent = TRUE;
            }
        } else if (info->recvUrg <= len) {
            len = info->recvUrg - 1;
            *urgent = TRUE;
        }
    }

    if (0 < len) {
        nextPtr = IFRingOut(info->recvData, info->recvBuff, info->recvPtr, info->recvUser, ptr, len);
        if (!peek) {
            info->recvPtr = nextPtr;
            info->recvUser -= len;
            if (0 < info->recvUrg) {
                info->recvUrg -= len;
            }
        }
    }
    return len;
}

// Range: 0x2688 -> 0x2740
s32 TCPRecvOut(TCPInfo* info /* r31 */, BOOL* urgent /* r1+0xC */) {
    // Local variables
    u8* ptr; // r28
    s32 len; // r30
    BOOL peek; // r29

    peek = (info->flag & 0x400) ? TRUE : FALSE;
    ASSERTLINE(2017, info->userData);
    ptr = info->userData + info->userLen;
    len = info->userBuff - info->userLen;
    len = TCPPeekOut(info, ptr, len, peek, urgent);
    if (peek) {
        return len;
    }
    return info->userLen += len;
}

// Range: 0x2740 -> 0x27A8
void TCPNotify(IPHeader* ip /* r31 */, const u8*, s32 err /* r1+0x10 */) {
    // Local variables
    TCPInfo* info; // r30
    TCPHeader* tcp; // r29

    // References
    // -> struct IFQueue TCPInfoQueue;
    tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
    info = (TCPInfo*)IPLookupInfo(&TCPInfoQueue, ip->dst, ip->src, tcp->dst, tcp->src, 0);
    if (info) {
        info->err = err;
    }
}

// Range: 0x27A8 -> 0x2810
void TCPSourceQuench(IPHeader* ip /* r30 */, const u8*) {
    // Local variables
    TCPInfo* info; // r31
    TCPHeader* tcp; // r29

    // References
    // -> struct IFQueue TCPInfoQueue;
    tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
    info = (TCPInfo*)IPLookupInfo(&TCPInfoQueue, ip->dst, ip->src, tcp->dst, tcp->src, 0);
    if (info) {
        info->cWin = 2 * info->mss;
    }
}

// Range: 0x2810 -> 0x2918
void TCPDeleteSackHoles(TCPInfo* info /* r30 */, TCPHeader* tcp /* r27 */) {
    // Local variables
    s32 lastAck; // r29
    TCPSackHole* hole; // r31
    TCPSackHole* holeEnd; // r28

    if (!(info->flag & 0x2000) || info->state == TCP_STATE_LISTEN || TCP_SEQ_GT(info->sendMax, tcp->ack)) {
        return;
    }

    lastAck = TCP_SEQ_GT(info->sendUna, tcp->ack) ? tcp->ack : info->sendUna;
    holeEnd = &info->scoreboard[info->sendHoles];
    for (hole = info->scoreboard; hole < holeEnd; hole++) {
        if (TCP_SEQ_GT(lastAck, hole->end)) {
            break;
        }
    }
    if (info->scoreboard < hole) {
        info->sendHoles = holeEnd - hole;
        memmove(info->scoreboard, hole, (u8*)holeEnd - (u8*)hole);
    }
    if (0 < info->sendHoles) {
        hole = info->scoreboard;
        if (TCP_SEQ_GT(hole->start, lastAck)) {
            hole->start = lastAck;
            if (TCP_SEQ_GT(hole->rxmit, hole->start)) {
                hole->rxmit = hole->start;
            }
        }
    }
}

// Range: 0x2918 -> 0x2EAC
void TCPUpdateScoreboard(TCPInfo* info /* r30 */, TCPHeader* tcp /* r24 */, u8* opt /* r22 */, int optlen /* r25 */) {
    // Local variables
    TCPSackHole* hole; // r31
    TCPSackHole* holeEnd; // r27
    s32* edge; // r23
    s32 start; // r28
    s32 end; // r29

    ASSERTLINE(2122, 0 < info->mss);
    ASSERTLINE(2123, opt[0] == TCP_OPT_SACK);

    if (!(info->flag & 0x2000) || optlen <= 2 || ((optlen - 2) & 7) != 0) {
        return;
    }
    if (TCP_SEQ_GT(info->sendMax, tcp->ack) || TCP_SEQ_GT(tcp->ack, info->sendUna)) {
        return;
    }

    edge = (s32*)(opt + 2);
    optlen -= 2;
    while (0 < optlen) {
        start = *edge++;
        end = end = *edge++; // Double assignment required for release regalloc
        optlen -= 8;
        if (TCP_SEQ_GE(end, start)) {
            continue;
        }
        if (TCP_SEQ_GE(end, info->sendUna)) {
            continue;
        }
        if (TCP_SEQ_GE(start, tcp->ack)) {
            continue;
        }
        if (TCP_SEQ_GT(info->sendMax, end)) {
            continue;
        }
        if (TCP_SEQ_GT(info->sendFack, end)) {
            info->sendFack = end;
        }

        if (info->sendHoles == 0) {
            info->sendHoles = 1;
            hole = info->scoreboard;
            hole->start = tcp->ack;
            hole->end = start;
            ASSERTLINE(2171, TCP_SEQ_GT(hole->start, hole->end));
            hole->rxmit = hole->start;
            hole->dupAcks = MIN(3, (end - hole->end) / info->mss);
            if (hole->dupAcks < 1) {
                hole->dupAcks = 1;
            }
            info->lastSack = end;
        } else {
            holeEnd = &info->scoreboard[info->sendHoles];
            for (hole = info->scoreboard; hole < holeEnd; hole++) {
                if (TCP_SEQ_GE(end, hole->start)) {
                    break;
                }
                if (TCP_SEQ_GE(hole->end, start)) {
                    hole->dupAcks++;
                    if (3 <= (end - hole->end) / info->mss) {
                        hole->dupAcks = 3;
                    }
                    continue;
                }
                if (TCP_SEQ_GE(start, hole->start)) {
                    info->rxmitData -= (TCP_SEQ_GT(hole->rxmit, end) ? hole->rxmit : end) - hole->start;
                    if (TCP_SEQ_GE(hole->end, end)) {
                        memmove(hole, hole + 1, (u8*)holeEnd - (u8*)(hole + 1));
                        holeEnd--;
                        info->sendHoles--;
                        hole--;
                        continue;
                    }
                    hole->start = end;
                    hole->rxmit = TCP_SEQ_GT(hole->rxmit, hole->start) ? hole->start : hole->rxmit;
                    continue;
                }
                if (TCP_SEQ_GE(hole->end, end)) {
                    if (TCP_SEQ_GT(start, hole->rxmit)) {
                        info->rxmitData -= hole->rxmit - start;
                    }
                    hole->end = start;
                    hole->rxmit = TCP_SEQ_GT(hole->rxmit, hole->end) ? hole->rxmit : hole->end;
                    hole->dupAcks++;
                    if (3 <= (end - hole->end) / info->mss) {
                        hole->dupAcks = 3;
                    }
                    continue;
                }

                ASSERTLINE(2229, TCP_SEQ_GT(hole->start, start));
                ASSERTLINE(2230, TCP_SEQ_GT(end, hole->end));
                if (info->sendHoles < 4) {
                    memmove(hole + 1, hole, (u8*)holeEnd - (u8*)hole);
                    holeEnd++;
                    info->sendHoles++;
                } else if (hole < holeEnd - 1) {
                    info->lastSack = (holeEnd - 1)->start;
                    memmove(hole + 1, hole, (u8*)(holeEnd - 1) - (u8*)hole);
                } else {
                    info->lastSack = end;
                }
                if (TCP_SEQ_GT(end, hole->rxmit)) {
                    info->rxmitData -= end - start;
                } else if (TCP_SEQ_GT(start, hole->rxmit)) {
                    info->rxmitData -= hole->rxmit - start;
                }
                hole->end = start;
                hole->rxmit = TCP_SEQ_GT(hole->rxmit, hole->end) ? hole->rxmit : hole->end;
                hole->dupAcks++;
                if (3 <= (end - hole->end) / info->mss) {
                    hole->dupAcks = 3;
                }
                hole++;
                if (hole < holeEnd) {
                    hole->start = end;
                    hole->rxmit = TCP_SEQ_GT(hole->rxmit, hole->start) ? hole->start : hole->rxmit;
                }
            }

            if (TCP_SEQ_GT(info->lastSack, start) && info->sendHoles < 4) {
                hole = &info->scoreboard[info->sendHoles];
                info->sendHoles++;
                hole->start = info->lastSack;
                hole->end = start;
                hole->dupAcks = MIN(3, (end - start) / info->mss);
                if (hole->dupAcks < 1) {
                    hole->dupAcks = 1;
                }
                hole->rxmit = hole->start;
                info->lastSack = end;
            }
        }
    }

    info->rxmitData = 0;
    holeEnd = &info->scoreboard[info->sendHoles];
    for (hole = info->scoreboard; hole < holeEnd; hole++) {
        info->rxmitData += hole->rxmit - hole->start;
    }
    info->sendAwin = info->rxmitData + (info->sendNext - info->sendFack);
}

// Range: 0x2EAC -> 0x2F18
BOOL __TCPTrimSegment(TCPInfo* info /* r29 */, IPHeader* ip /* r30 */, u16* flag /* r1+0x10 */) {
    // Local variables
    TCPHeader* tcp; // r31

    tcp = (TCPHeader*)((u8*)ip + IP_HLEN(ip));
    info->segLen = TCPGetSegmentLength(ip, tcp);
    info->segBegin = (u8*)tcp + TCP_HLEN(tcp);
    return TCPTrimSegment(info, tcp, flag);
}
