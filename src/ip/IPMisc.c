#include <dolphin/ip.h>
#include <dolphin/private/ip.h>
#include <ctype.h>

#ifdef NULL
#undef NULL
#endif

#define NULL 0

// Range: 0x0 -> 0xA0
int stricmp(const char* s1 /* r1+0x8 */, const char* s2 /* r1+0xC */) {
    // Local variables
    char c1; // r31
    char c2; // r30

    do {
        c1 = (char)tolower(*s1++);
        c2 = (char)tolower(*s2++);
        if (c1 < c2) {
            return -1;
        }
        if (c1 > c2) {
            return 1;
        }
    } while (c1);
    return 0;
}

// Range: 0xA0 -> 0x164
int strnicmp(const char* s1 /* r1+0x8 */, const char* s2 /* r1+0xC */, u32 n /* r1+0x10 */) {
    // Local variables
    int i; // r30
    char c1; // r31
    char c2; // r29

    for (i = 0; i < n; i++) {
        c1 = (char)tolower(*s1++);
        c2 = (char)tolower(*s2++);
        if (c1 < c2) {
            return -1;
        }
        if (c1 > c2) {
            return 1;
        }
        if (!c1) {
            return 0;
        }
    }
    return 0;
}
