#include <dolphin/ip.h>
#include <dolphin/private/ip.h>
#include <dolphin/os/OSReset.h>
#include <dolphin/ip/IPArp.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

static BOOL OnReset(BOOL final);
static void GoCallback(u8 ltps);

#ifdef DEBUG
const char* __IPVersion = "<< Dolphin SDK - IP\tdebug build: Mar  9 2004 12:31:05 (0x2301) >>";
#else
const char* __IPVersion = "<< Dolphin SDK - IP\trelease build: Mar  9 2004 12:57:37 (0x2301) >>";
#endif

static OSResetFunctionInfo ResetFunctionInfo = { OnReset, 111, NULL, NULL }; // size: 0x10, address: 0x44
static u16 Protocols[4] = { ETH_IP, ETH_ARP, ETH_PPPoE_DISCOVERY, ETH_PPPoE_SESSION }; // size: 0x8, address: 0x4
static u8 HwBroadcastAddr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // size: 0x6, address: 0xC
static u8 RecvBuf[1518] ATTRIBUTE_ALIGN(32); // size: 0x5EE, address: 0x0
static u8 SendBuf[1518] ATTRIBUTE_ALIGN(32); // size: 0x5EE, address: 0x600
static IFFifo SendFifo; // size: 0x10, address: 0xBF0
static u8 SendHeap[16384] ATTRIBUTE_ALIGN(32); // size: 0x4000, address: 0xC00
static s32 Loopback; // size: 0x4, address: 0x0
static IFDatagram* Sending; // size: 0x4, address: 0x4
static IFQueue SendQueue; // size: 0x8, address: 0x8
static s32 LinkState; // size: 0x4, address: 0x10
static OSAlarm LinkAlarm; // size: 0x28, address: 0x4C00
static s32 Reset; // size: 0x4, address: 0x14
static s32 Mute = TRUE; // size: 0x4, address: 0x14
static struct {
    s32 len; // offset 0x0, size 0x4
    IFDatagram datagram; // offset 0x4, size 0x3C
    IFVec vec[3]; // offset 0x40, size 0x18
} Current; // size: 0x58, address: 0x4C28

IPInterface __IFDefault; // size: 0xA8, address: 0x4C80

// Range: 0x0 -> 0x8
static BOOL NullFilter(IPInterface*, void*, s32) {
    return TRUE;
}

// Range: 0x8 -> 0x204
void ETHIn(IPInterface* interface /* r31 */, ETHHeader* eh /* r29 */, s32 len /* r24 */) {
    // Local variables
    u32 flag; // r28
    IPHeader* ip; // r30
    BOOL localSrc; // r26
    BOOL localDst; // r25

    // References
    // -> unsigned char IPAddrAny[4];
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char HwBroadcastAddr[6];
    if (!interface->inFilter(interface, eh, len)) {
        return;
    }

    if (memcmp(eh->dst, HwBroadcastAddr, 6) == 0) {
        flag = 1;
        __IFDefault.stat.inNonUcastPackets++;
    } else if (eh->dst[0] == 1) {
        flag = 2;
        __IFDefault.stat.inNonUcastPackets++;
    } else {
        flag = 0;
        __IFDefault.stat.inUcastPackets++;
    }

    switch (eh->type) {
        case ETH_ARP:
            ARPIn(interface, eh, len, flag);
            break;
        case ETH_IP:
            ip = (IPHeader*)((u8*)eh + sizeof(ETHHeader));
            if (ip->src[0] == 127 || ip->dst[0] == 127 || IPEQ(ip->src, ip->dst)) {
                break;
            }
            localSrc = localDst = FALSE;
            if (IPNEQ(interface->addr, IPAddrAny)) {
                localSrc |= IPEQ(interface->addr, ip->src);
                localDst |= IPEQ(interface->addr, ip->dst);
            }
            if (IPNEQ(interface->alias, IPAddrAny)) {
                localSrc |= IPEQ(interface->alias, ip->src);
                localDst |= IPEQ(interface->alias, ip->dst);
            }
            if (!localSrc || !localDst) {
                IPIn(interface, ip, len - sizeof(ETHHeader), flag);
            }
            break;
        case ETH_PPPoE_DISCOVERY:
        case ETH_PPPoE_SESSION:
            PPPoEIn(interface, eh, len, flag);
            break;
    }
}

// Range: 0x204 -> 0x264
static void* Callback0(u16 type /* r3 */) {
    // References
    // -> static unsigned char RecvBuf[1518];
    // -> static long Reset;
    switch (type) {
        case ETH_IP:
        case ETH_ARP:
        case ETH_PPPoE_DISCOVERY:
        case ETH_PPPoE_SESSION:
            if (!Reset) {
                return RecvBuf;
            }
            break;
    }
    return NULL;
}

// Range: 0x264 -> 0x2AC
static void Callback1(u8* rbuf /* r1+0x8 */, s32 len /* r31 */) {
    // References
    // -> struct IPInterface __IFDefault;
    if (len >= 18) {
        ETHIn(&__IFDefault, (ETHHeader*)rbuf, len - 4);
    }
}

// Range: 0x2AC -> 0x758
static BOOL Go(void) {
    // Local variables
    BOOL enabled; // r20
    IFDatagram* datagram; // r31
    ETHHeader* eh; // r24
    s32 len; // r27
    u8* ptr; // r26
    IFVec* vec; // r28
    IFVec* end; // r22
    BOOL loopback; // r21
    BOOL eth; // r19
    BOOL discard; // r1+0x8
    int dlen; // r18

    // References
    // -> static unsigned char SendBuf[1518];
    // -> struct IPInterface __IFDefault;
    // -> static struct [anonymous] Current;
    // -> static struct IFFifo SendFifo;
    // -> static struct IFQueue SendQueue;
    // -> static struct IFDatagram * Sending;
    // -> static unsigned short Protocols[4];
    // -> static long Loopback;
    switch (__IFDefault.type) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
            eth = TRUE;
            break;
        default:
            eth = FALSE;
            break;
    }

    enabled = OSDisableInterrupts();
    ASSERTLINE(389, !IFIsEmptyQueue(&SendQueue) || SendFifo.used == 0);
    if (Loopback || Sending || IFIsEmptyQueue(&SendQueue)) {
        OSRestoreInterrupts(enabled);
        return FALSE;
    }

#ifdef DEBUG
    {
        int i; // r23

        datagram = (IFDatagram*)SendQueue.next;
        for (i = 0; i < ARRAY_COUNT(Protocols); i++) {
            if (datagram->type == Protocols[i]) {
                break;
            }
        }
        ASSERTMSGLINE(409, i < ARRAY_COUNT(Protocols), "Sending illegal packet type.");
    }
#endif

    datagram = (IFDatagram*)SendQueue.next;
    ASSERTLINE(419, datagram->queue == &SendQueue);
    ASSERTLINE(420, datagram->interface == &__IFDefault);
    Sending = datagram;
    dlen = sizeof(IFDatagram) + ((datagram->nVec > 1) ? (datagram->nVec - 1) * sizeof(IFVec) : 0);
    memmove(&Current.datagram, datagram, dlen);
#ifdef DEBUG
    if (datagram->type == ETH_IP) {
        IPHeader* ip; // r17

        ip = (IPHeader*)datagram->vec[0].data;
        ASSERTLINE(432, IPCheckSum(ip) == 0);
    }
#endif

    eh = (ETHHeader*)SendBuf;
    eh->type = datagram->type;
    memmove(eh->dst, datagram->hwAddr, 6);
    memmove(eh->src, __IFDefault.mac, 6);
    len = sizeof(ETHHeader);
    ptr = SendBuf + sizeof(ETHHeader);
    if (datagram->prefixLen) {
        ASSERTLINE(446, datagram->type == ETH_PPPoE_SESSION);
        memmove(ptr, datagram->prefix, datagram->prefixLen);
        len += datagram->prefixLen;
        ptr += datagram->prefixLen;
    }

    switch (datagram->type) {
        case ETH_IP:
            len += IPFragment(datagram, ptr, &discard);
            ptr += len;
            break;
        case ETH_PPPoE_SESSION:
            if (len >= 22 && *(u16*)(SendBuf + 20) == 0x0021) {
                len += IPFragment(datagram, ptr, &discard);
                ptr += len;
                break;
            }
        default:
            for (vec = datagram->vec, end = &datagram->vec[datagram->nVec]; vec && vec < end; vec++) {
                memmove(ptr, vec->data, vec->len);
                len += vec->len;
                ptr += vec->len;
            }
            discard = TRUE;
            break;
    }

    if (len < 60) {
        memset(ptr, 0, 60 - len);
    }

    if (discard) {
        IFQueueDequeueHead(IFDatagram*, &SendQueue, datagram);
        datagram->queue = NULL;
        IFFifoFree(&SendFifo, datagram, dlen);
        datagram = &Current.datagram;
        for (vec = datagram->vec, end = &datagram->vec[datagram->nVec]; vec && vec < end; vec++) {
            IFFifoFree(&SendFifo, vec->data, vec->len);
        }
    } else {
        datagram->callback = NULL;
    }
    ASSERTLINE(517, !IFIsEmptyQueue(&SendQueue) || SendFifo.used == 0);

    datagram->flag &= ~1;
    if (!__IFDefault.outFilter(&__IFDefault, SendBuf, len)) {
        datagram->flag |= 1;
    }

    if (datagram->flag & 1) {
        loopback = TRUE;
    } else if (eth && memcmp(datagram->hwAddr, __IFDefault.mac, 6) != 0) {
        loopback = FALSE;
        Current.len = len;
        if (eh->dst[0] & 1) {
            __IFDefault.stat.outNonUcastPackets++;
        } else {
            __IFDefault.stat.outUcastPackets++;
        }
        ETHSendAsync(SendBuf, len, GoCallback);
    } else {
        loopback = TRUE;
    }
    OSRestoreInterrupts(enabled);
    return loopback;
}

// Range: 0x758 -> 0x988
static void GoCallback(u8 ltps /* r24 */) {
    // Local variables
    IFDatagram* datagram; // r30
    void* param; // r25
    void (*callback)(void*, s32); // r28
    s32 rc; // r27
    BOOL eth; // r26
    IPHeader* ip; // r29

    // References
    // -> static struct IFDatagram * Sending;
    // -> static long Loopback;
    // -> struct IPInterface __IFDefault;
    // -> static unsigned char SendBuf[1518];
    // -> static unsigned char SendHeap[16384];
    // -> static unsigned char HwBroadcastAddr[6];
    // -> static struct [anonymous] Current;
    // -> static long LinkState;
    do {
        ASSERTLINE(564, Sending);
        switch (__IFDefault.type) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                eth = TRUE;
                break;
            default:
                eth = FALSE;
                break;
        }

        rc = 0;
        if (eth) {
            ETHGetLinkStateAsync(&LinkState);
            if (ltps & 0xF) {
                __IFDefault.stat.outCollisions++;
            }
            if (ltps & 0x80) {
                __IFDefault.stat.outErrors++;
            }
        }

        if (Sending != (IFDatagram*)-1) {
            datagram = &Current.datagram;
            callback = datagram->callback;
            param = datagram->param;
            if (datagram->flag & 1) {
                Loopback = 0;
            } else if (memcmp(datagram->hwAddr, __IFDefault.mac, 6) == 0) {
                Loopback = 1;
            } else if (datagram->type == ETH_IP) {
                if (memcmp(datagram->hwAddr, HwBroadcastAddr, 6) == 0) {
                    Loopback = 2;
                } else if (datagram->hwAddr[0] == 1) {
                    Loopback = 3;
                }
            }

            if ((u8*)Sending < SendHeap || SendHeap + sizeof(SendHeap) <= (u8*)Sending) {
                Sending->interface = NULL;
            }

            if (callback) {
                callback(param, rc);
            }

            if (0 <= rc) {
                ip = (IPHeader*)(SendBuf + sizeof(ETHHeader));
                switch (Loopback) {
                    case 1:
                        IPIn(&__IFDefault, ip, ip->len, 4);
                        break;
                    case 2:
                        IPIn(&__IFDefault, ip, ip->len, 5);
                        break;
                    case 3:
                        IPIn(&__IFDefault, ip, ip->len, 6);
                        break;
                }
            }
            Loopback = 0;
        }
        Sending = NULL;
    } while (Go());
}

// Range: 0x988 -> 0xB2C
void ETHOut(IPInterface* interface /* r27 */, IFDatagram* datagram /* r31 */) {
    // Local variables
    BOOL enabled; // r26

    // References
    // -> static struct IFQueue SendQueue;
    enabled = OSDisableInterrupts();
    ASSERTLINE(696, 0 < datagram->nVec && datagram->nVec <= IF_MAX_VEC);
    datagram->queue = NULL;
    datagram->interface = interface;
    datagram->offset = 0;
    switch (datagram->type) {
        case ETH_ARP:
        case ETH_PPPoE_DISCOVERY:
        case ETH_PPPoE_SESSION:
            datagram->queue = &SendQueue;
            IFQueueEnqueueTail(IFDatagram*, &SendQueue, datagram);
            break;
        case ETH_IP:
            switch (ARPLookup(interface, datagram->dst, datagram->hwAddr)) {
                case -1:
                    ARPHold(interface, datagram);
                    break;
                case 0:
                case 1:
                default:
                    datagram->queue = &SendQueue;
                    IFQueueEnqueueTail(IFDatagram*, &SendQueue, datagram);
#ifdef DEBUG
                    {
                        IPHeader* ip; // r25

                        ip = (IPHeader*)datagram->vec[0].data;
                        ASSERTLINE(725, IPCheckSum(ip) == 0);
                    }
#endif
                    break;
            }
            break;
    }
    OSRestoreInterrupts(enabled);

    if (Go()) {
        GoCallback(0);
    }
}

// Range: 0xB2C -> 0xBFC
static void Cancel(IPInterface* interface /* r1+0x8 */, IFDatagram* datagram /* r29 */) {
    // Local variables
    BOOL enabled; // r28

    // References
    // -> static struct IFDatagram * Sending;
    enabled = OSDisableInterrupts();
    ASSERTLINE(765, datagram->interface == interface);
    if (Sending == datagram) {
        Sending = (IFDatagram*)-1;
    }
    if (datagram->queue) {
        IFQueueDequeueEntry(IFDatagram*, datagram->queue, datagram);
        datagram->queue = NULL;
    }
    datagram->interface = NULL;
    OSRestoreInterrupts(enabled);
}

// Range: 0xBFC -> 0xC2C
static void* Alloc(IPInterface*, s32 len /* r1+0xC */) {
    // References
    // -> static struct IFFifo SendFifo;
    return IFFifoAlloc(&SendFifo, len);
}

// Range: 0xC2C -> 0xC64
static BOOL Free(IPInterface*, void* ptr /* r1+0xC */, s32 len /* r1+0x10 */) {
    // References
    // -> static struct IFFifo SendFifo;
    return IFFifoFree(&SendFifo, ptr, len);
}

// Range: 0xC64 -> 0xD18
static void LinkCheckHandler(OSAlarm*, OSContext*) {
    // Local variables
    BOOL up; // r30

    // References
    // -> struct IPInterface __IFDefault;
    // -> static long LinkState;
    // -> unsigned char IPAddrAny[4];
    ASSERTLINE(820, __IFDefault.type != IF_TYPE_NONE);
    up = __IFDefault.up;
    ETHGetLinkStateAsync(&LinkState);
    __IFDefault.up = LinkState;
    if (!up && LinkState == TRUE) {
        DHCPReboot();
        if (IPNEQ(__IFDefault.alias, IPAddrAny)) {
            IPAutoConfig();
        }
    }
    if (up && LinkState == FALSE) {
        IPSetConfigError(&__IFDefault, -0x70);
    }
}

// Range: 0xD18 -> 0xF20
BOOL IFInit(s32 type /* r30 */) {
    static BOOL initialized;

    // References
    // -> static struct OSResetFunctionInfo ResetFunctionInfo;
    // -> static long LinkState;
    // -> struct IPInterface __IFDefault;
    // -> static struct OSAlarm LinkAlarm;
    // -> static unsigned short Protocols[4];
    // -> static long Reset;
    // -> unsigned char IPLimited[4];
    // -> static unsigned char SendHeap[16384];
    // -> static struct IFFifo SendFifo;
    // -> static struct IFQueue SendQueue;
    // -> const char * __IPVersion;
    // -> static int initialized$224;
    if (initialized) {
        IFMute(FALSE);
        return TRUE;
    }
    initialized = TRUE;
    OSRegisterVersion(__IPVersion);

    switch (type) {
        case 0:
            type = 0;
            break;
        case 1:
            type = 1;
            break;
        case 2:
            type = 2;
            break;
        case 3:
            type = 3;
            break;
        case 4:
            type = 4;
            break;
        default:
            type = IF_TYPE_NONE;
            break;
    }

    OSCreateAlarm(&__IFDefault.gratuitousAlarm);
    IFQueueInit(&SendQueue);
    IFFifoInit(&SendFifo, SendHeap, sizeof(SendHeap));
    IPInitRoute(NULL, NULL, NULL);
    ARPInit();
    __IFDefault.mtu = 1500;
    memcpy(__IFDefault.broadcast, IPLimited, 4);
    __IFDefault.out = ETHOut;
    __IFDefault.cancel = Cancel;
    __IFDefault.alloc = Alloc;
    __IFDefault.free = Free;
    __IFDefault.inFilter = __IFDefault.outFilter = NullFilter;
    IFQueueInit(&__IFDefault.queue);
    Reset = FALSE;

    if (ETHInit(type) == 1) {
        __IFDefault.type = type;
        __IFDefault.up = LinkState = FALSE;
        ETHGetMACAddr(__IFDefault.mac);
        ETHSetProtoType(Protocols, ARRAY_COUNT(Protocols));
        IFMute(FALSE);
        OSCreateAlarm(&LinkAlarm);
        OSSetPeriodicAlarm(&LinkAlarm, OSGetTime(), OSMillisecondsToTicks(250), LinkCheckHandler);
        IGMPInit(&__IFDefault);
    } else {
        __IFDefault.type = IF_TYPE_NONE;
        __IFDefault.up = LinkState = FALSE;
    }
    OSRegisterResetFunction(&ResetFunctionInfo);
    return TRUE;
}

// Range: 0xF20 -> 0xFB8
BOOL IFMute(BOOL mute /* r30 */) {
    // Local variables
    BOOL prev; // r31

    // References
    // -> struct IPInterface __IFDefault;
    // -> static long Mute;
    prev = Mute;
    Mute = mute;
    switch (__IFDefault.type) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
            if (mute && !prev) {
                ETHSetRecvCallback(NULL, NULL);
                ETHClearMulticastAddresses();
            } else if (!mute && prev) {
                ETHSetRecvCallback(Callback0, Callback1);
            }
            break;
    }
    return prev;
}

// Range: 0xFB8 -> 0x1064
static BOOL OnReset(BOOL final /* r31 */) {
    // References
    // -> static struct IFQueue SendQueue;
    // -> static struct IFDatagram * Sending;
    // -> static long Reset;
    Reset = TRUE;
    if (final) {
        UDPOnReset(final);
        TCPOnReset(final);
        IGMPOnReset(final);
        return TRUE;
    }

    if (UDPOnReset(final) && TCPOnReset(final)) {
        if (Sending || !IFIsEmptyQueue(&SendQueue)) {
            return FALSE;
        }
        IFMute(TRUE);
        return TRUE;
    }
    return FALSE;
}
