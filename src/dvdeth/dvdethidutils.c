#include <dolphin/os.h>
#include <dolphin/dvdeth.h>
#include <string.h>

#ifdef NULL
#undef NULL
#endif
#define NULL ((void*)0)

// Range: 0x0 -> 0x44
static u32 strnlen(const char* str /* r3 */, u32 maxlen /* r4 */) {
    // Local variables
    u32 i; // r31

    for (i = 0; i < maxlen; i++) {
        if (*str++ == '\0') {
            return i;
        }
    }
    return maxlen;
}

// Range: 0x44 -> 0x3C4
int DVDCompareDiskID(const DVDDiskID* id1 /* r29 */, const DVDDiskID* id2 /* r30 */) {
#ifdef DEBUG
    // Local variables
    const char* game1; // r21
    const char* game2; // r20
    const char* company1; // r23
    const char* company2; // r22
    u8 diskNum1; // r27
    u8 diskNum2; // r26
    u8 version1; // r25
    u8 version2; // r24
    u32 length; // r28
#endif

    ASSERTMSGLINE(59, id1, "DVDCompareDiskID(): Specified id1 is NULL\n");
    ASSERTMSGLINE(60, id2, "DVDCompareDiskID(): Specified id2 is NULL\n");

#ifdef DEBUG
    game1 = id1->gameName;
    game2 = id2->gameName;
    company1 = id1->company;
    company2 = id2->company;
    diskNum1 = id1->diskNumber;
    diskNum2 = id2->diskNumber;
    version1 = id1->gameVersion;
    version2 = id2->gameVersion;

    length = strnlen(game1, 4);
    ASSERTMSGLINE(73, length == 0 || length == 4, "DVDCompareDiskID(): Specified game name for id1 is neither NULL nor 4 character long\n");
    ASSERTMSGLINE(74, company1, "DVDCompareDiskID(): Specified company name for id1 is NULL\n");
    ASSERTMSGLINE(75, company1[1] != '\0', "DVDCompareDiskID(): Specified company name for id1 is not 2 character long\n");
    ASSERTMSGLINE(76, diskNum1 == 0xff || (diskNum1 / 16 < 10 && diskNum1 % 16 < 10), "DVDCompareDiskID(): Specified disk number for id1 is neither 0xff nor a BCD number");
    ASSERTMSGLINE(77, version1 == 0xff || (version1 / 16 < 10 && version1 % 16 < 10), "DVDCompareDiskID(): Specified version number for id1 is neither 0xff nor a BCD number");

    length = strnlen(game2, 4);
    ASSERTMSGLINE(80, length == 0 || length == 4, "DVDCompareDiskID(): Specified game name for id2 is neither NULL nor 4 character long\n");
    ASSERTMSGLINE(81, company2, "DVDCompareDiskID(): Specified company name for id2 is NULL\n");
    ASSERTMSGLINE(82, company2[1] != '\0', "DVDCompareDiskID(): Specified company name for id2 is not 2 character long\n");
    ASSERTMSGLINE(83, diskNum2 == 0xff || (diskNum2 / 16 < 10 && diskNum2 % 16 < 10), "DVDCompareDiskID(): Specified disk number for id2 is neither 0xff nor a BCD number");
    ASSERTMSGLINE(84, version2 == 0xff || (version2 / 16 < 10 && version2 % 16 < 10), "DVDCompareDiskID(): Specified version number for id2 is neither 0xff nor a BCD number");
#endif

    if (id1->gameName[0] != '\0' && id2->gameName[0] != '\0' && strncmp(id1->gameName, id2->gameName, 4) != 0) {
        return FALSE;
    }

    if (id1->company[0] == '\0' || id2->company[0] == '\0' || strncmp(id1->company, id2->company, 2) != 0) {
        return FALSE;
    }

    if (id1->diskNumber != 0xff && id2->diskNumber != 0xff && id1->diskNumber != id2->diskNumber) {
        return FALSE;
    }

    if (id1->gameVersion != 0xff && id2->gameVersion != 0xff && id1->gameVersion != id2->gameVersion) {
        return FALSE;
    }

    return TRUE;
}

// Range: 0x3C4 -> 0x584
DVDDiskID* DVDGenerateDiskID(DVDDiskID* id /* r30 */, const char* game /* r26 */, const char* company /* r27 */, u8 diskNum /* r28 */, u8 version /* r29 */) {
    ASSERTMSGLINE(118, id, "DVDGenerateDiskID(): Specified id is NULL\n");
    ASSERTMSGLINE(119, game == NULL || strlen(game) == 4, "DVDGenerateDiskID(): Specified game name is neither NULL nor 4 character long\n");
    ASSERTMSGLINE(120, company, "DVDGenerateDiskID(): Specified company name is NULL\n");
    ASSERTMSGLINE(121, strlen(company) == 2, "DVDGenerateDiskID(): Specified company name is not 2 character long\n");
    ASSERTMSGLINE(122, diskNum == 0xff || (diskNum / 16 < 10 && diskNum % 16 < 10), "DVDGenerateDiskID(): Specified disk number is neither 0xff nor a BCD number");
    ASSERTMSGLINE(123, version == 0xff || (version / 16 < 10 && version % 16 < 10), "DVDGenerateDiskID(): Specified version number is neither 0xff nor a BCD number");

    memset(id, 0, sizeof(DVDDiskID));

    if (game != NULL) {
        strncpy(id->gameName, game, 4);
    }

    if (company != NULL) {
        strncpy(id->company, company, 2);
    }

    id->diskNumber = diskNum;
    id->gameVersion = version;

    return id;
}
