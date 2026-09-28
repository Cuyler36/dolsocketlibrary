#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

static u16 Port = 49152; // size: 0x2, address: 0x0
IFQueue UDPInfoQueue; // size: 0x8, address: 0x0

// Range: 0x0 -> 0xF8
static s32 PeekInput(UDPInfo* info /* r31 */, void* ptr /* r1+0xC */, s32 len /* r28 */, s32 offset /* r27 */) {
    // Local variables
    u8* head; // r30
    IFVec vec[2]; // r1+0x18
    int i; // r29
    int n; // r26

    if (info->recvUsed < offset + len) {
        len = info->recvUsed - offset;
    }
    if (len <= 0) {
        return 0;
    }

    head = info->recvPtr + offset;
    if (info->recvPtr + info->recvBuff <= head) {
        head -= info->recvBuff;
    }
    n = IFRingGet(info->recvRing, info->recvBuff, head, info->recvUsed - offset, vec, len);
    for (i = 0, head = ptr; i < n; i++) {
        memmove(head, vec[i].data, vec[i].len);
        head += vec[i].len;
    }
    return len;
}

// Range: 0xF8 -> 0x184
static void DiscardInput(UDPInfo* info /* r31 */, IPHeader* ip /* r30 */) {
    ASSERTLINE(206, ip->len + sizeof(u32) <= info->recvUsed);
    info->recvPtr = IFRingPut(info->recvRing, info->recvBuff, info->recvPtr, info->recvUsed, ip->len + sizeof(u32));
    info->recvUsed -= ip->len + sizeof(u32);
}

// Range: 0x184 -> 0x238
static IPHeader* SaveInput(UDPInfo* info /* r31 */, IPHeader* ip /* r30 */, u32 flag /* r1+0x10 */) {
    if (info->recvBuff - info->recvUsed < ip->len + sizeof(u32)) {
        return NULL;
    }
    info->recvPtr = IFRingIn(info->recvRing, info->recvBuff, info->recvPtr, info->recvUsed, (u8*)ip, ip->len);
    info->recvUsed += ip->len;
    info->recvPtr = IFRingIn(info->recvRing, info->recvBuff, info->recvPtr, info->recvUsed, (u8*)&flag, sizeof(u32));
    info->recvUsed += sizeof(u32);
    return ip;
}

// Range: 0x238 -> 0x2CC
static void CopySockets(IPHeader* ip /* r28 */, UDPHeader* udp /* r29 */, IPSocket* local /* r30 */, IPSocket* remote /* r31 */) {
    if (local) {
        local->len = IP_SOCKLEN;
        local->family = IP_INET;
        memmove(local->addr, ip->dst, IP_ALEN);
        local->port = udp->dst;
    }
    if (remote) {
        remote->len = IP_SOCKLEN;
        remote->family = IP_INET;
        memmove(remote->addr, ip->src, IP_ALEN);
        remote->port = udp->src;
    }
}

// Range: 0x2CC -> 0x2D0
static void NullCallback() {}

// Range: 0x2D0 -> 0x2FC
static void SyncCallback(UDPInfo* info /* r1+0x8 */, s32) {
    OSWakeupThread(&info->queueThread);
}

// Range: 0x2FC -> 0x43C
u16 UDPCheckSum(IFVec* vec /* r29 */, s32 nVec /* r24 */) {
    // Local variables
    IPHeader* ip; // r30
    s32 hlen; // r26
    u16* p; // r25
    s32 len; // r27
    u32 sum; // r31

    sum = 0;
    ASSERTLINE(280, 0 < nVec);
    ASSERTLINE(281, IP_MIN_HLEN + UDP_HLEN <= vec->len);
    ip = (IPHeader*)vec->data;
    ASSERTLINE(285, ip->proto == IP_PROTO_UDP);
    hlen = IP_HLEN(ip);

    sum += *(u16*)&ip->src[0];
    sum += *(u16*)&ip->src[2];
    sum += *(u16*)&ip->dst[0];
    sum += *(u16*)&ip->dst[2];
    sum += IP_PROTO_UDP;
    sum += ip->len - hlen;

    p = (u16*)((u8*)ip + hlen);
    len = vec->len - hlen;
    for (;;) {
        while (1 < len) {
            sum += *p++;
            len -= 2;
        }
        if (len == 1) {
            sum += *(u8*)p << 8;
        }
        if (--nVec <= 0) {
            break;
        }
        ++vec;
        p = (u16*)vec->data;
        len = vec->len;
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return sum ^ 0xFFFF;
}

// Range: 0x43C -> 0x4A0
s32 UDPGetRemoteSocket(UDPInfo* info /* r29 */, IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = IPGetRemoteSocket(&info->pair, socket);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x4A0 -> 0x504
s32 UDPGetLocalSocket(UDPInfo* info /* r29 */, IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = IPGetLocalSocket(&info->pair, socket);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x504 -> 0x570
s32 UDPSetOption(UDPInfo* info /* r29 */, u8 ttl /* r1+0xC */, u8 tos /* r1+0xD */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = IPSetOption(&info->pair, ttl, tos);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x570 -> 0x5F0
s32 UDPBind(UDPInfo* info /* r30 */, const IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    // References
    // -> struct IFQueue UDPInfoQueue;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = IPBind(&UDPInfoQueue, &info->pair, socket, (info->flag & 0x10000) ? TRUE : FALSE);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x5F0 -> 0x65C
s32 UDPConnect(UDPInfo* info /* r29 */, const IPSocket* socket /* r1+0xC */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    // References
    // -> static unsigned short Port;
    // -> struct IFQueue UDPInfoQueue;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = IPConnect(&UDPInfoQueue, &info->pair, socket, &Port);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x65C -> 0x6D8
s32 UDPGetRecvBuff(UDPInfo* info /* r30 */, void* recvbuf /* r27 */, s32* recvbufLen /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = 0;
        if (recvbufLen) {
            *recvbufLen = info->recvBuff;
        }
        if (recvbuf) {
            *(u8**)recvbuf = info->recvRing;
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x6D8 -> 0x74C
s32 UDPSetRecvBuff(UDPInfo* info /* r31 */, void* recvbuf /* r28 */, s32 recvbufLen /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else {
        rc = 0;
        info->recvRing = recvbuf;
        info->recvBuff = recvbufLen;
        info->recvPtr = recvbuf;
        info->recvUsed = 0;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x74C -> 0x7C8
s32 UDPGetSendBuff(UDPInfo* info /* r30 */, void* sendbuf /* r27 */, s32* sendbufLen /* r28 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r31

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
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

// Range: 0x7C8 -> 0x850
s32 UDPSetSendBuff(UDPInfo* info /* r31 */, void* sendbuf /* r1+0xC */, s32 sendbufLen /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r29
    s32 rc; // r30

    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else if (info->sendUsed != 0) {
        rc = IP_ERR_BUSY;
    } else {
        rc = 0;
        info->sendData = sendbuf;
        info->sendBuff = sendbufLen;
        info->sendUsed = 0;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x850 -> 0x990
s32 UDPOpen(UDPInfo* info /* r31 */, void* recvbuf /* r27 */, s32 recvbufLen /* r1+0x10 */) {
    // Local variables
    BOOL enabled; // r29
    BOOL used; // r28
    // IFQueue* ___prev; // r30 (IFQueueEnqueueTail)

    // References
    // -> struct IFQueue UDPInfoQueue;
    if (info == NULL) {
        return -12;
    }

    enabled = OSDisableInterrupts();
    used = __IPIsMember(&UDPInfoQueue, &info->pair);
    OSRestoreInterrupts(enabled);
    if (used) {
        return -5;
    }

    memset(info, 0, sizeof(UDPInfo));
    info->pair.proto = IP_PROTO_UDP;
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

    info->recvRing = recvbuf;
    info->recvBuff = recvbufLen;
    info->recvPtr = recvbuf;
    info->recvUsed = 0;

    enabled = OSDisableInterrupts();
    do {
        register IFQueue* ___prev;

        ___prev = UDPInfoQueue.prev;
        if (___prev == NULL) {
            UDPInfoQueue.next = (IFQueue*)&info->pair;
        } else {
            ((IPInfo*)___prev)->link.next = (IFQueue*)&info->pair;
        }
        info->pair.link.prev = ___prev;
        info->pair.link.next = NULL;
        UDPInfoQueue.prev = (IFQueue*)&info->pair;
    } while (0);
    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0x990 -> 0xAF8
static void SendCallback(UDPInfo* info /* r31 */, s32 result /* r29 */) {
    // Local variables
    UDPCallback callback; // r28

    ASSERTLINE(569, info->datagram.interface == NULL);
    ASSERTLINE(570, info->datagram.queue == NULL);
    result = (result < 0) ? result : info->datagram.vec[1].len;
    if (info->sendResult) {
        *info->sendResult = result;
        info->sendResult = NULL;
    }

    if (info->sendData) {
        ASSERTLINE(581, info->sendCallback == NULL);
        ASSERTLINE(582, 0 < info->sendUsed);
        info->sendUsed = 0;
    } else {
        ASSERTLINE(587, info->sendCallback != NULL);
        callback = info->sendCallback;
        info->sendCallback = NULL;
        callback(info, result);
    }

    if (0 < info->pair.poll && info->sendData == NULL) {
        __IPWakeupPollingThreads();
    }
}

// Range: 0xAF8 -> 0xFE0
s32 UDPSendAsync(UDPInfo* info /* r31 */, void* data /* r20 */, s32 len /* r27 */, const IPSocket* remote /* r23 */, UDPCallback callback /* r22 */, s32* result /* r25 */) {
    // Local variables
    BOOL enabled; // r21
    IPHeader* ip; // r30
    UDPHeader* udp; // r26
    s32 rc; // r28
    IFDatagram* datagram; // r29
    IPInterface* interface; // r24

    // References
    // -> struct IPInterface __IFDefault;
    // -> unsigned char IPAddrAny[4];
    // -> unsigned char IPLoopbackAddr[4];
    // -> static unsigned short Port;
    // -> struct IFQueue UDPInfoQueue;
    interface = NULL;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
        goto error;
    }

    if (info->pair.local.port == 0) {
        info->pair.local.port = IPGetAnonPort(&UDPInfoQueue, &Port);
        if (info->pair.local.port == 0) {
            rc = -7;
            goto error;
        }
    }

    if (len < 0 || 65535 - IP_MIN_HLEN - UDP_HLEN < len) {
        rc = -17;
        goto error;
    }

    if (info->sendCallback && info->sendData == NULL) {
        rc = IP_ERR_BUSY;
        goto error;
    }

    if (info->pair.remote.port == 0) {
        if (remote == NULL) {
            rc = -6;
            goto error;
        }
        if (remote->len != IP_SOCKLEN || remote->family != IP_INET || remote->port == 0 || IP_CLASSE(remote->addr)) {
            rc = -12;
            goto error;
        }
        if (IPEQ(remote->addr, IPAddrAny)) {
            rc = -13;
            goto error;
        }
    }

    if (info->sendData && info->sendBuff < len) {
        rc = -17;
        goto error;
    }

    if (info->sendData == NULL) {
        ip = (IPHeader*)info->header;
        udp = (UDPHeader*)(info->header + IP_MIN_HLEN);
        datagram = &info->datagram;
        IFInitDatagram(datagram, ETH_IP, 2);
        info->sendCallback = callback ? callback : NullCallback;
        info->sendResult = result;
        if (result) {
            *result = IP_ERR_BUSY;
        }
        datagram->vec[1].data = data;
        datagram->callback = (void (*)(void*, s32))SendCallback;
    } else if (info->sendUsed <= 0) {
        ip = (IPHeader*)info->header;
        udp = (UDPHeader*)(info->header + IP_MIN_HLEN);
        datagram = &info->datagram;
        IFInitDatagram(datagram, ETH_IP, 2);
        memmove(info->sendData, data, len);
        info->sendUsed = len;
        datagram->vec[1].data = info->sendData;
        datagram->callback = (void (*)(void*, s32))SendCallback;
    } else {
        interface = &__IFDefault;
        datagram = (IFDatagram*)interface->alloc(interface, sizeof(IFDatagram) + sizeof(IFVec) + IP_MIN_HLEN + UDP_HLEN + len);
        if (datagram == NULL) {
            interface->stat.outDiscards++;
            rc = -7;
            goto error;
        }
        IFInitDatagram(datagram, ETH_IP, 2);
        ip = (IPHeader*)((u8*)datagram + sizeof(IFDatagram) + sizeof(IFVec));
        udp = (UDPHeader*)((u8*)ip + IP_MIN_HLEN);
        memmove((u8*)udp + UDP_HLEN, data, len);
        datagram->vec[1].data = (u8*)udp + UDP_HLEN;
    }

    ip->verlen = 0x45;
    ip->tos = info->pair.tos;
    ip->len = IP_HLEN(ip) + UDP_HLEN + len;
    ip->proto = IP_PROTO_UDP;
    ip->frag = 0;
    udp->src = info->pair.local.port;
    udp->len = len + UDP_HLEN;
    udp->sum = 0;
    if (info->pair.remote.port != 0) {
        udp->dst = info->pair.remote.port;
        memmove(ip->dst, info->pair.remote.addr, IP_ALEN);
    } else {
        udp->dst = remote->port;
        memmove(ip->dst, remote->addr, IP_ALEN);
    }
    ip->ttl = IP_CLASSD(ip->dst) ? info->pair.mttl : info->pair.ttl;

    if (!IP_CLASSD(info->pair.local.addr) && IPNEQ(info->pair.local.addr, IPAddrAny)) {
        memmove(ip->src, info->pair.local.addr, IP_ALEN);
    } else if (ip->dst[0] == 127) {
        memmove(ip->src, IPLoopbackAddr, IP_ALEN);
    } else if (memcmp(ip->dst, __IFDefault.alias, 2) == 0 || IPEQ(__IFDefault.addr, IPAddrAny)) {
        memmove(ip->src, __IFDefault.alias, IP_ALEN);
    } else {
        memmove(ip->src, __IFDefault.addr, IP_ALEN);
    }

    datagram->vec[0].data = ip;
    datagram->vec[0].len = IP_HLEN(ip) + UDP_HLEN;
    datagram->vec[1].len = len;
    datagram->param = info;
    rc = IPOut(datagram);
    if (rc < 0) {
        if (result) {
            *result = rc;
        }
        info->sendCallback = NULL;
        if (0 < info->pair.poll && info->sendData == NULL) {
            __IPWakeupPollingThreads();
        }
        if (interface) {
            interface->free(interface, datagram, sizeof(IFDatagram) + sizeof(IFVec) + IP_MIN_HLEN + UDP_HLEN + len);
        }
    } else if (info->sendData) {
        if (result) {
            *result = len;
        }
        if (callback) {
            callback(info, len);
        }
    }
    OSRestoreInterrupts(enabled);
    return rc;

error:
    if (result) {
        *result = rc;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0xFE0 -> 0x1074
s32 UDPSend(UDPInfo* info /* r29 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, const IPSocket* remote /* r1+0x14 */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x18
    s32 rc; // r31

    rc = UDPSendAsync(info, data, len, remote, SyncCallback, &result);
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

// Range: 0x1074 -> 0x12D0
s32 UDPReceiveExAsync(UDPInfo* info /* r31 */, void* data /* r22 */, s32 len /* r28 */, IPSocket* local /* r23 */, IPSocket* remote /* r24 */, u32 flag /* r26 */, UDPCallback callback /* r27 */, s32* result /* r29 */) {
    // Local variables
    BOOL enabled; // r25
    s32 rc; // r30
    IPHeader ip; // r1+0x30
    UDPHeader udp; // r1+0x28

    rc = 0;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else if (len < 0) {
        rc = -17;
    } else if (info->pair.local.port == 0) {
        rc = -4;
    } else if (info->recvCallback && !(flag & 4)) {
        rc = IP_ERR_BUSY;
    }

    if (rc != 0) {
        if (result) {
            *result = rc;
        }
        OSRestoreInterrupts(enabled);
        return rc;
    }

    callback = callback ? callback : NullCallback;
    if (0 < info->recvUsed) {
        rc = PeekInput(info, &ip, sizeof(IPHeader), 0);
        ASSERTLINE(886, rc == sizeof(IPHeader));
        rc = PeekInput(info, &udp, sizeof(UDPHeader), IP_HLEN(&ip));
        ASSERTLINE(888, rc == sizeof(UDPHeader));
        len = (udp.len - UDP_HLEN < len) ? udp.len - UDP_HLEN : len;
        rc = PeekInput(info, data, len, IP_HLEN(&ip) + UDP_HLEN);
        CopySockets(&ip, &udp, local, remote);
        if (!(flag & 2)) {
            DiscardInput(info, &ip);
        }
        if (result) {
            *result = udp.len - UDP_HLEN;
        }
        callback(info, udp.len - UDP_HLEN);
    } else if (flag & 4) {
        rc = -9;
        if (result) {
            *result = rc;
        }
    } else {
        if (flag & 2) {
            info->flag |= 0x400;
        } else {
            info->flag &= ~0x400;
        }
        info->recvCallback = callback;
        info->recvResult = result;
        if (result) {
            *result = IP_ERR_BUSY;
        }
        info->data = data;
        info->len = len;
        info->remote = remote;
        info->local = local;
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x12D0 -> 0x132C
s32 UDPReceiveAsync(UDPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, IPSocket* local /* r1+0x14 */, IPSocket* remote /* r1+0x18 */, UDPCallback callback /* r1+0x1C */, s32* result /* r1+0x20 */) {
    return UDPReceiveExAsync(info, data, len, local, remote, 0, callback, result);
}

// Range: 0x132C -> 0x13A0
s32 UDPReceiveNonblock(UDPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, IPSocket* local /* r1+0x14 */, IPSocket* remote /* r1+0x18 */) {
    // Local variables
    s32 rc; // r31
    s32 result; // r1+0x1C

    rc = UDPReceiveExAsync(info, data, len, local, remote, 4, NULL, &result);
    if (rc == 0) {
        return result;
    }
    return rc;
}

// Range: 0x13A0 -> 0x1444
s32 UDPReceiveEx(UDPInfo* info /* r29 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, IPSocket* local /* r1+0x14 */, IPSocket* remote /* r1+0x18 */, u32 flag /* r1+0x1C */) {
    // Local variables
    BOOL enabled; // r30
    s32 result; // r1+0x20
    s32 rc; // r31

    rc = UDPReceiveExAsync(info, data, len, local, remote, flag, SyncCallback, &result);
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

// Range: 0x1444 -> 0x1490
s32 UDPReceive(UDPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, IPSocket* local /* r1+0x14 */, IPSocket* remote /* r1+0x18 */) {
    return UDPReceiveEx(info, data, len, local, remote, 0);
}

// Range: 0x1490 -> 0x15C0
static void Cancel(UDPInfo* info /* r31 */, s32 result /* r30 */) {
    // Local variables
    UDPCallback sendCallback; // r27
    UDPCallback recvCallback; // r26
    s32* sendResult; // r29
    s32* recvResult; // r28

    IPCancel(&info->datagram);
    sendCallback = info->sendCallback;
    recvCallback = info->recvCallback;
    sendResult = info->sendResult;
    recvResult = info->recvResult;
    info->sendResult = NULL;
    info->recvResult = NULL;
    if (result == -8) {
        info->sendCallback = NullCallback;
        info->recvCallback = NullCallback;
    } else {
        info->sendCallback = NULL;
        info->recvCallback = NULL;
    }

    if (sendCallback) {
        if (sendResult) {
            ASSERTLINE(1028, *sendResult == IP_ERR_BUSY);
            *sendResult = result;
        }
        sendCallback(info, result);
    }

    if (recvCallback) {
        if (recvResult) {
            ASSERTLINE(1038, *recvResult == IP_ERR_BUSY);
            *recvResult = result;
        }
        recvCallback(info, result);
    }

    if (0 < info->pair.poll) {
        __IPWakeupPollingThreads();
    }
}

// Range: 0x15C0 -> 0x1634
s32 UDPCancel(UDPInfo* info /* r29 */) {
    // Local variables
    BOOL enabled; // r30
    s32 rc; // r31

    rc = 0;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    }
    if (rc != 0) {
        OSRestoreInterrupts(enabled);
        return rc;
    }

    Cancel(info, -16);
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x1634 -> 0x16F4
s32 UDPClose(UDPInfo* info /* r29 */) {
    // Local variables
    BOOL enabled; // r27
    s32 rc; // r28
    // IFQueue* ___next; // r31 (IFQueueDequeueEntry)
    // IFQueue* ___prev; // r30 (IFQueueDequeueEntry)

    // References
    // -> struct IFQueue UDPInfoQueue;
    rc = 0;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    }
    if (rc != 0) {
        OSRestoreInterrupts(enabled);
        return rc;
    }

    Cancel(info, -8);
    IPClose(&info->pair);

    do {
        register IFQueue* ___next;
        register IFQueue* ___prev;

        ___next = info->pair.link.next;
        ___prev = info->pair.link.prev;
        if (___next == NULL) {
            UDPInfoQueue.prev = ___prev;
        } else {
            ((IPInfo*)___next)->link.prev = ___prev;
        }
        if (___prev == NULL) {
            UDPInfoQueue.next = ___next;
        } else {
            ((IPInfo*)___prev)->link.next = ___next;
        }
    } while (0);

    info->pair.proto = 0;
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x16F4 -> 0x180C
s32 UDPGetSockOpt(UDPInfo* info /* r27 */, int level /* r28 */, int optname /* r25 */, void* optval /* r29 */, int* optlen /* r30 */) {
    // Local variables
    BOOL enabled; // r26
    s32 rc; // r31

    rc = -14;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else if (level == 0xFFFF) {
        switch (optname) {
            case 0x0004:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = (info->flag & 0x10000) ? TRUE : FALSE;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
            case 0x1008:
                if (*optlen >= sizeof(int)) {
                    *(int*)optval = 2;
                    *optlen = sizeof(int);
                    rc = 0;
                } else {
                    rc = -12;
                }
                break;
        }
    } else if (level == 0) {
        rc = IPGetSockOpt(&info->pair, level, optname, optval, optlen);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x180C -> 0x18EC
s32 UDPSetSockOpt(UDPInfo* info /* r30 */, int level /* r29 */, int optname /* r25 */, void* optval /* r26 */, int optlen /* r27 */) {
    // Local variables
    BOOL enabled; // r28
    s32 rc; // r31

    rc = -14;
    enabled = OSDisableInterrupts();
    if (info->pair.proto != IP_PROTO_UDP) {
        rc = -12;
    } else if (level == 0xFFFF) {
        switch (optname) {
            case 0x0004:
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
        }
    } else if (level == 0) {
        rc = IPSetSockOpt(&info->pair, level, optname, optval, optlen);
    }
    OSRestoreInterrupts(enabled);
    return rc;
}

// Range: 0x18EC -> 0x1950
s16 __UDPPoll(UDPInfo* info /* r3 */) {
    // Local variables
    s16 event; // r31

    if (info->pair.proto != IP_PROTO_UDP) {
        return 0x80;
    }

    event = 0;
    if (info->sendCallback == NULL || info->sendData != NULL) {
        event |= 0x8;
    }
    if (0 < info->recvUsed) {
        event |= 0x1;
    }
    return event;
}

// Range: 0x1950 -> 0x1B60
void UDPIn(IPInterface* interface /* r25 */, IPHeader* ip /* r30 */, u32 flag /* r27 */) {
    // Local variables
    UDPInfo* info; // r31
    UDPHeader* udp; // r29
    UDPCallback callback; // r28
    void* data; // r1+0x24
    s32 len; // r26
    IFVec vec; // r1+0x1C
    ICMPUnreachable ur; // r1+0x14

    // References
    // -> struct IFQueue UDPInfoQueue;
    udp = (UDPHeader*)((u8*)ip + IP_HLEN(ip));
    if (ip->len < IP_HLEN(ip) + UDP_HLEN || ip->len < IP_HLEN(ip) + udp->len || udp->len < sizeof(UDPHeader)) {
        return;
    }

    vec.data = ip;
    vec.len = ip->len;
    if (udp->sum != 0 && UDPCheckSum(&vec, 1) != 0) {
        return;
    }

    data = (u8*)udp + UDP_HLEN;
    info = (UDPInfo*)IPLookupInfo(&UDPInfoQueue, ip->src, ip->dst, udp->src, udp->dst, flag);
    if (info == NULL) {
        if (flag == 0) {
            ur.type = 3;
            ur.code = 3;
            ur.unused = 0;
            ur.mtu = 0;
            ICMPSendError((ICMPHeader*)&ur, interface, ip, flag);
        }
        return;
    }

    callback = info->recvCallback;
    if (callback == NULL || (info->flag & 0x400)) {
        ip = SaveInput(info, ip, flag);
        if (ip == NULL) {
            interface->stat.inDiscards++;
            return;
        }
        if (0 < info->pair.poll) {
            __IPWakeupPollingThreads();
        }
    }

    if (callback) {
        len = (info->len < udp->len - UDP_HLEN) ? info->len : udp->len - UDP_HLEN;
        memmove(info->data, (u8*)udp + UDP_HLEN, len);
        CopySockets(ip, udp, info->local, info->remote);
        if (info->recvResult) {
            *info->recvResult = udp->len - UDP_HLEN;
            info->recvResult = NULL;
        }
        info->recvCallback = NULL;
        callback(info, udp->len - UDP_HLEN);
    }
}

// Range: 0x1B60 -> 0x1C58
void UDPNotify(IPHeader* ip /* r29 */, const u8*, s32 err /* r1+0x10 */) {
    // Local variables
    UDPHeader* udp; // r30
    IPInfo* info; // r31
    IPInfo* next; // r28
    UDPInfo* match; // r27

    // References
    // -> unsigned char IPAddrAny[4];
    // -> struct IFQueue UDPInfoQueue;
    udp = (UDPHeader*)((u8*)ip + IP_HLEN(ip));
    if (udp->dst == 0) {
        return;
    }

    IFQueueIterator(IPInfo*, &UDPInfoQueue, info, next) {
        if (info->local.port != 0 && info->local.port == udp->src &&
            (IPEQ(info->local.addr, IPAddrAny) || IPEQ(info->local.addr, ip->src)) && info->remote.port == udp->dst &&
            IPEQ(info->remote.addr, ip->dst)) {
            match = (UDPInfo*)info;
            Cancel(match, err);
        }
    }
}

// Range: 0x1C58 -> 0x1CAC
s32 UDPPeek(UDPInfo* info /* r1+0x8 */, void* data /* r1+0xC */, s32 len /* r1+0x10 */, IPSocket* local /* r1+0x14 */, IPSocket* remote /* r1+0x18 */) {
    return UDPReceiveExAsync(info, data, len, local, remote, 6, NULL, NULL);
}

// Range: 0x1CAC -> 0x1D08
BOOL UDPOnReset(BOOL) {
    // Local variables
    UDPInfo* info; // r31

    // References
    // -> struct IFQueue UDPInfoQueue;
    if (UDPInfoQueue.next == NULL) {
        return TRUE;
    }

    while (UDPInfoQueue.next != NULL) {
        info = (UDPInfo*)UDPInfoQueue.next;
        UDPClose(info);
    }
    return FALSE;
}
