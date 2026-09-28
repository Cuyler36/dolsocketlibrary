#include <dolphin/ip.h>
#include <dolphin/private/ip.h>

static IPReassembleControl Control; // size: 0x40, address: 0x0

// Range: 0x0 -> 0xD0
static void TimeoutHandler(OSAlarm*, OSContext*) {
    // Local variables
    IPReassembled* packet; // r31
    IPHeader* header; // r29
    IPHeader* first; // r28
    ICMPTimeExceeded te; // r1+0x10

    // References
    // -> static struct IPReassembleControl Control;
    if (Control.buffer != NULL) {
        for (packet = (IPReassembled*)Control.buffer; (u8*)packet < Control.buffer + Control.len;
             packet = (IPReassembled*)((u8*)packet + Control.size)) {
            header = &packet->header;
            if (header->verlen == 0) {
                continue;
            }
            if (header->ttl <= 1) {
                header->verlen = 0;
                first = &packet->first;
                if (first->verlen != 0) {
                    te.type = 11;
                    te.code = 1;
                    te.unused = 0;
                    ICMPSendError((ICMPHeader*)&te, packet->interface, first, packet->flag);
                }
            } else {
                header->ttl--;
            }
        }
    }
}

// Range: 0xD0 -> 0x20C
s32 IPSetReassemblyBuffer(void* buffer /* r27 */, s32 len /* r28 */, s32 mtu /* r30 */) {
    // Local variables
    BOOL enabled; // r26
    s32 size; // r29

    // References
    // -> static struct IPReassembleControl Control;
    mtu = (mtu > 576) ? mtu : 576;
    mtu = (mtu < 65535) ? mtu : 65535;
    size = mtu + 0x54;
    size = OSRoundUp32B(size);
    if (buffer == NULL || len < size) {
        if (Control.flag & 1) {
            OSCancelAlarm(&Control.alarm);
            Control.flag &= ~1;
        }
        return -12;
    }

    len -= len % size;
    memset(buffer, 0, len);

    enabled = OSDisableInterrupts();
    Control.buffer = buffer;
    Control.len = len;
    Control.mtu = mtu;
    Control.size = size;
    if (!(Control.flag & 1)) {
        Control.flag |= 1;
        OSCreateAlarm(&Control.alarm);
        OSSetPeriodicAlarm(&Control.alarm, OSGetTime(), OSSecondsToTicks(1), TimeoutHandler);
    }
    OSRestoreInterrupts(enabled);
    return 0;
}

// Range: 0x20C -> 0x4C8
static IPHeader* Reassemble(IPHeader* packet /* r31 */, IPHeader* frag /* r30 */, s32 mtu /* r1+0x10 */) {
    // Local variables
    IPHole* hole; // r24
    IPHole* newHole; // r27
    s32 first; // r26
    s32 last; // r25
    u16* next; // r29
    s32 len; // r22
    s32 offset; // r23
    s32 packetLen; // r21
    u16 holeFirst; // r19
    u16 holeLast; // r20

    ASSERTLINE(222, packet->id == frag->id && packet->proto == frag->proto && IP_ADDR_EQ(packet->src, frag->src) && IP_ADDR_EQ(packet->dst, frag->dst));
    ASSERTLINE(223, (frag->frag & IP_MF) || IP_FRAG(frag) != 0);
    ASSERTLINE(224, packet->verlen != 0);

    first = IP_FRAG(frag);
    len = frag->len - IP_HLEN(frag);
    last = first + len - 1;
    packetLen = IP_HLEN(packet) + last + 1;
    if (mtu < packetLen || len <= 0 || ((frag->frag & IP_MF) && len % 8 != 0)) {
        packet->verlen = 0;
        return NULL;
    }

    packet->len = (packet->len > packetLen) ? packet->len : packetLen;

    next = &packet->sum;
    while (*next != 1) {
        hole = (IPHole*)((u8*)packet + IP_HLEN(packet) + *next);
        if (hole->last < first || last < hole->first) {
            next = &hole->next;
            continue;
        }

        holeFirst = hole->first;
        holeLast = hole->last;
        *next = hole->next;
        if (holeFirst < first) {
            newHole = hole;
            newHole->last = first - 1;
            *next = newHole->first;
            next = &newHole->next;
            offset = 0;
        } else {
            offset = holeFirst - first;
        }

        if (last < holeLast) {
            if (frag->frag & IP_MF) {
                newHole = (IPHole*)((u8*)packet + IP_HLEN(packet) + last + 1);
                newHole->first = last + 1;
                newHole->last = holeLast;
                newHole->next = *next;
                *next = newHole->first;
                next = &newHole->next;
            } else {
                *next = 1;
            }
        } else {
            last = holeLast;
        }

        ASSERTLINE(292, 0 <= last - (first + offset) + 1);
        memmove((u8*)packet + IP_HLEN(packet) + first + offset, (u8*)frag + IP_HLEN(frag) + offset, last - (first + offset) + 1);
    }

    if (packet->sum == 1) {
        return packet;
    }
    return NULL;
}

// Range: 0x4C8 -> 0x654
static BOOL SaveFirstFragment(IPReassembled* packet /* r27 */, IPHeader* frag /* r31 */) {
    // Local variables
    IPHeader* header; // r30
    s32 optlen; // r29

    // References
    // -> static struct IPReassembleControl Control;
    if (IP_FRAG(frag) != 0) {
        return TRUE;
    }
    if (frag->len < IP_HLEN(frag) + 8) {
        return FALSE;
    }
    if (packet->first.verlen != 0) {
        if (IP_HLEN(frag) == IP_HLEN(&packet->first)) {
            return TRUE;
        }
        return FALSE;
    }

    memmove(&packet->first, frag, IP_HLEN(frag) + 8);
    header = &packet->header;
    if (IP_HLEN(header) == IP_HLEN(frag)) {
        return TRUE;
    }

    ASSERTLINE(338, IP_HLEN(header) == IP_MIN_HLEN);
    optlen = IP_HLEN(frag) - IP_MIN_HLEN;
    ASSERTLINE(340, 0 < optlen);
    if (Control.mtu < header->len + optlen) {
        return FALSE;
    }

    memmove((u8*)header + IP_HLEN(frag), (u8*)header + IP_MIN_HLEN, header->len - IP_MIN_HLEN + 8);
    memmove((u8*)header + IP_MIN_HLEN, (u8*)frag + IP_MIN_HLEN, optlen);
    header->verlen = frag->verlen;
    header->len += optlen;
    return TRUE;
}

// Range: 0x654 -> 0x8D4
IPHeader* IPReassemble(IPInterface* interface /* r24 */, IPHeader* frag /* r30 */, u32 flag /* r25 */) {
    // Local variables
    IPReassembled* free; // r28
    IPReassembled* packet; // r29
    IPHeader* header; // r31
    IPHole* hole; // r26

    // References
    // -> static struct IPReassembleControl Control;
    if (Control.buffer == NULL) {
        return NULL;
    }

    free = NULL;
    for (packet = (IPReassembled*)Control.buffer; (u8*)packet < Control.buffer + Control.len;
         packet = (IPReassembled*)((u8*)packet + Control.size)) {
        header = &packet->header;
        if (header->verlen == 0) {
            if (free == NULL) {
                free = packet;
            }
            continue;
        }

        if (header->id == frag->id && header->proto == frag->proto && IP_ADDR_EQ(header->src, frag->src) &&
            IP_ADDR_EQ(header->dst, frag->dst)) {
            if (packet->interface != interface || packet->flag != flag) {
                header->verlen = 0;
                return NULL;
            }
            if (frag->proto == IP_PROTO_TCP && IP_FRAG(frag) == 8) {
                header->verlen = 0;
                return NULL;
            }
            if (!SaveFirstFragment(packet, frag)) {
                header->verlen = 0;
                return NULL;
            }

            header = Reassemble(header, frag, Control.mtu);
            if (header) {
                header->frag &= ~(IP_DF | IP_MF | IP_FRAG_BITS);
                header->tos = packet->first.tos;
                header->ttl = packet->first.ttl;
                header->sum = 0;
                header->sum = IPCheckSum(header);
            }
            return header;
        }
    }

    if (frag->proto == IP_PROTO_TCP && IP_FRAG(frag) == 8) {
        return NULL;
    }

    if (free) {
        free->interface = interface;
        free->flag = flag;
        free->first.verlen = 0;
        header = &free->header;
        memmove(header, frag, sizeof(IPHeader));
        header->verlen = 0x45;
        header->ttl = 60;
        header->sum = 0;
        header->len = 20;
        hole = (IPHole*)((u8*)header + IP_HLEN(header));
        hole->first = 0;
        hole->last = Control.mtu - IP_HLEN(header);
        hole->next = 1;
        if (!SaveFirstFragment(free, frag)) {
            header->verlen = 0;
            return NULL;
        }
        Reassemble(header, frag, Control.mtu);
    }
    return NULL;
}

// Range: 0x8D4 -> 0x9A8
static u8* VecMove(IFDatagram* datagram /* r23 */, int voffset /* r24 */, u8* ptr /* r25 */, int len /* r26 */) {
    // Local variables
    IFVec* vec; // r31
    IFVec* end; // r22
    int offset; // r29
    int gap; // r28
    int vlen; // r30
    int vend; // r27

    offset = 0;
    vend = voffset + len;
    for (vec = datagram->vec, end = &datagram->vec[datagram->nVec]; 0 < len && vec < end; offset += vec->len, vec++) {
        if (voffset < offset + vec->len && offset < vend) {
            gap = voffset - offset;
            if (gap < 0) {
                gap = 0;
            }
            vlen = vend - offset;
            vlen = (vlen < vec->len) ? vlen : vec->len;
            vlen -= gap;
            len -= vlen;
            memmove(ptr, (u8*)vec->data + gap, vlen);
            ptr += vlen;
        }
    }
    return ptr;
}

// Range: 0x9A8 -> 0xD0C
int IPFragment(IFDatagram* datagram /* r29 */, u8* ptr /* r27 */, BOOL* discard /* r19 */) {
    // Local variables
    IPInterface* interface; // r21
    IPHeader* org; // r30
    IPHeader* frag; // r26
    IFVec* vec; // r24
    IFVec* end; // r18
    int len; // r31
    int hlen; // r28
    u8* opt; // r22
    int optlen; // r20
    int i; // r23

    interface = datagram->interface;
    *discard = TRUE;
    org = (IPHeader*)datagram->vec[0].data;
    ASSERTLINE(524, datagram->type == ETH_IP || datagram->type == ETH_PPPoE_SESSION);
    ASSERTLINE(525, IPCheckSum(org) == 0);
    ASSERTLINE(526, interface);

    if (org->len <= interface->mtu) {
        len = 0;
        for (vec = datagram->vec, end = &datagram->vec[datagram->nVec]; vec < end; vec++) {
            memmove(ptr, vec->data, vec->len);
            len += vec->len;
            ptr += vec->len;
        }
        return org->len;
    }

    ASSERTLINE(546, (org->frag & IP_DF) == 0);
    *discard = FALSE;
    frag = (IPHeader*)ptr;
    if (datagram->offset == 0) {
        hlen = IP_HLEN(org);
        memmove(ptr, org, hlen);
        ptr += hlen;
        len = (interface->mtu - hlen) & ~7;
        VecMove(datagram, datagram->offset + hlen, ptr, len);
        frag->verlen = 0x40 | (hlen >> 2);
        frag->len = hlen + len;
        frag->frag = IP_MF;
    } else {
        memmove(ptr, org, IP_MIN_HLEN);
        ptr += IP_MIN_HLEN;
        optlen = IP_HLEN(org) - IP_MIN_HLEN;
        ASSERTLINE(580, 0 <= optlen);
        opt = (u8*)(org + 1);
        for (i = 0; i < optlen && opt[i] != 0; i += len) {
            switch (opt[i]) {
                case 0:
                case 1:
                    len = 1;
                    break;
                default:
                    len = opt[i + 1];
                    break;
            }
            if (opt[i] & 0x80) {
                memmove(ptr, opt, len);
                ptr += len;
            }
        }

        hlen = ptr - (u8*)frag;
        while (hlen % 4 != 0) {
            *ptr++ = 0;
            hlen++;
        }

        len = (interface->mtu - hlen) & ~7;
        len = (len < org->len - IP_HLEN(org) - datagram->offset) ? len : org->len - IP_HLEN(org) - datagram->offset;
        VecMove(datagram, datagram->offset + IP_HLEN(org), ptr, len);
        frag->verlen = 0x40 | (hlen >> 2);
        frag->len = hlen + len;
        frag->frag = datagram->offset >> 3;
        if (IP_HLEN(org) + datagram->offset + len < org->len) {
            frag->frag |= IP_MF;
        } else {
            *discard = TRUE;
        }
    }

    frag->sum = 0;
    frag->sum = IPCheckSum(frag);
    datagram->offset += len;
    return hlen + len;
}
