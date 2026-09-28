#include <dolphin/ip.h>
#include <dolphin/ip/IPArp.h>
#include <dolphin/private/ip.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

int __TCPMaxPersist = 3840; // size: 0x4, address: 0x0

// Range: 0x0 -> 0x380
static void TCPRxmitTimeOut(OSAlarm* alarm /* r1+0x8 */, OSContext*) {
    // Local variables
    TCPInfo* info; // r31
    IPHeader* header; // r30
    OSTime r2; // r28

    // References
    // -> int __TCPMaxPersist;
    // -> struct TCPStatistics TCPStat;

    TCPStat.rxmitTimeout++;
    info = (TCPInfo*)((u8*)alarm - offsetof(TCPInfo, rxmitAlarm));
    info->rxmitCount++;
    if (info->rxmitCount >= 16) {
        info->rxmitCount = 16;
    }
    info->rto *= 2;
    if (info->rttMax < info->rto) {
        info->rto = info->rttMax;
    }

    if (!(info->flag & 0x200)) {
        if (info->rxmitCount == 4 && info->state >= 4) {
            header = (IPHeader*)info->header;
            header->frag &= ~0x4000;
            if (info->sendBusy) {
                header->sum = 0;
                header->sum = IPCheckSum(header);
            }
            info->mss = (info->mss > 536) ? 536 : info->mss;
        }

        if (info->rxmitCount == 3) {
            if (IPIsLocalAddr(NULL, info->datagram.dst)) {
                ARPRevalidate(info->datagram.dst);
            } else {
                IPRecoverGateway(info->datagram.dst);
            }
        } else if (info->rxmitCount > 3) {
            switch (info->state) {
                case 2:
                case 3:
                    r2 = OSSecondsToTicks((OSTime)180);
                    if (info->iss == info->sendUna && info->r2 < r2) {
                        break;
                    }
                default:
                    r2 = info->r2;
                    break;
            }

            if (OSGetTime() - info->r0 >= r2) {
                if (info->err == 0) {
                    info->err = -10;
                }
                TCPAbort(info);
                return;
            }
        }
    } else {
        if (OSGetTime() - info->r0 >= OSSecondsToTicks((OSTime)__TCPMaxPersist)) {
            if (info->err == 0) {
                info->err = -10;
            }
            TCPAbort(info);
            return;
        }
    }

    info->sendNext = info->sendUna;
    info->rttTiming = FALSE;
    info->ssThresh = ((info->cWin < info->sendWin) ? info->cWin : info->sendWin) / 2;
    info->ssThresh = (info->ssThresh > 2 * info->mss) ? info->ssThresh : 2 * info->mss;
    info->cWin = 2 * info->mss;
    info->dupAcks = 0;
    info->sendHoles = 0;
    info->sendFack = info->sendUna;
    info->rxmitData = 0;
    info->sendAwin = 0;
    info->sendRecover = info->sendMax;
    TCPOutput(info, TCP_FLAG_ACK);
}

// Range: 0x380 -> 0x3E8
void TCPStartRxmitTimer(TCPInfo* info /* r31 */) {
    if (info->rxmitAlarm.handler == (OSAlarmHandler)NULL) {
        if (info->rxmitCount == 0) {
            info->r0 = OSGetTime();
        }
        OSSetAlarm(&info->rxmitAlarm, info->rto, TCPRxmitTimeOut);
    }
}

// Range: 0x3E8 -> 0x4CC
void TCPStopRxmitTimer(TCPInfo* info /* r31 */, TCPHeader*) {
    // Local variables
    s32 sendLen; // r30

    sendLen = info->sendLen;
    if (info->sendCallback && info->userSendLen > 0) {
        sendLen += info->userSendLen;
    }

    if (info->sendWin == 0 && sendLen > 0) {
        info->flag |= 0x200;
        info->r0 = OSGetTime();
        TCPStartRxmitTimer(info);
        return;
    }

    if (info->flag & 0x200) {
        info->flag &= ~0x200;
        info->rxmitCount = 0;
        OSCancelAlarm(&info->rxmitAlarm);
    }

    if (info->sendUna == info->sendMax) {
        info->flag &= ~0x200;
        info->rxmitCount = 0;
        OSCancelAlarm(&info->rxmitAlarm);
    } else {
        TCPStartRxmitTimer(info);
    }
}

// Range: 0x4CC -> 0x510
void TCPCancelRxmitTimer(TCPInfo* info /* r31 */) {
    info->flag &= ~0x200;
    info->rxmitCount = 0;
    OSCancelAlarm(&info->rxmitAlarm);
}

// Range: 0x510 -> 0x5E0
static OSTime CalcRto(TCPInfo* info /* r3 */) {
    info->rxmitCount = 0;
    info->rto = info->srtt + 4 * info->rttDe;
    if (info->rto < info->rttMin) {
        info->rto = info->rttMin;
    } else if (info->rttMax < info->rto) {
        info->rto = info->rttMax;
    }
    return info->rto;
}

// Range: 0x5E0 -> 0x71C
void TCPUpdateRtt(TCPInfo* info /* r31 */, OSTime rtt /* r1+0x10 */) {
    // Local variables
    OSTime delta; // r29

    info->rtt = rtt;
    if (info->srtt != 0) {
        delta = info->rtt - info->srtt;
        info->srtt += delta / 8;
        if (delta < 0) {
            delta = -delta;
        }
        info->rttDe += (delta - info->rttDe) / 4;
    } else {
        info->srtt = info->rtt;
        info->rttDe = info->rtt / 2;
    }
    CalcRto(info);
}

// Range: 0x71C -> 0x824
void TCPInitRtt(TCPInfo* info /* r31 */) {
    info->rtt = 0;
    info->srtt = 0;
    info->rttDe = OSMillisecondsToTicks((OSTime)750);
    info->rttMin = OSMillisecondsToTicks((OSTime)1000);
    info->rttMax = OSSecondsToTicks((OSTime)240);
    CalcRto(info);
}
