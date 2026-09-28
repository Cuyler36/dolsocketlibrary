#include <dolphin/os.h>
#include <dolphin/vi.h>
#include <dolphin/gx.h>
#include <dolphin/dvdeth.h>

#ifdef NULL
#undef NULL
#endif
#define NULL 0

void OSFatal(GXColor fg, GXColor bg, const char* msg);

static void (* FatalFunc)(); // size: 0x4, address: 0x0

const char* Japanese = "\n\n\n\203G\203\211\201[\202\252\224\255\220\266\202\265\202\334\202\265\202\275\201B\n\n\226{\221\314\202\314\203p\203\217\201[\203{\203^\203\223\202\360\211\237\202\265\202\304\223d\214\271\202\360OFF\202\311\202\265\201A\n\226{\221\314\202\314\216\346\210\265\220\340\226\276\217\221\202\314\216w\216\246\202\311\217]\202\301\202\304\202\255\202\276\202\263\202\242\201B"; // size: 0x4, address: 0x0

const char* English = "\n\n\nAn error has occurred.\nTurn the power off and refer to the\nNintendo GameCube Instruction Booklet\nfor further instructions."; // size: 0x4, address: 0x4

const char* const Europe[6] = { // size: 0x18, address: 0x0
    "\n\n\nAn error has occurred.\nTurn the power off and refer to the\nNintendo GameCube Instruction Booklet\nfor further instructions.",
    "\n\n\nEin Fehler ist aufgetreten.\nBitte schalten Sie den Nintendo GameCube\naus und lesen Sie die Bedienungsanleitung,\num weitere Informationen zu erhalten.",
    "\n\n\nUne erreur est survenue.\nEteignez la console et r\351f\351rez-vous au\nmanuel d'instructions Nintendo GameCube\npour de plus amples informations.",
    "\n\n\nSe ha producido un error.\nApaga la consola y consulta el manual\nde instrucciones de Nintendo GameCube\npara obtener m\341s informaci\363n.",
    "\n\n\nSi \350 verificato un errore.\nSpegni (OFF) e controlla il manuale\nd'istruzioni del Nintendo GameCube\nper ulteriori indicazioni.",
    "\n\n\nEr is een fout opgetreden.\nZet de Nintendo GameCube uit en\nraadpleeg de handleiding van de\nNintendo GameCube voor nadere\ninstructies.",
};

// Range: 0x0 -> 0x98
static void ShowMessage(void) {
    // Local variables
    const char* message; // r31
    GXColor bg = { 0, 0, 0, 0 }; // r1+0x14
    GXColor fg = { 255, 255, 255, 0 }; // r1+0x10

    // References
    // -> char * const Europe[6];
    // -> const char * English;
    // -> const char * Japanese;

    if (VIGetTvFormat() == VI_NTSC) {
        if (OSGetFontEncode() == OS_FONT_ENCODE_SJIS) {
            message = Japanese;
        } else {
            message = English;
        }
    } else {
        message = Europe[OSGetLanguage()];
    }

    OSFatal(fg, bg, message);
}

// Range: 0x98 -> 0x10C
BOOL DVDSetAutoFatalMessaging(BOOL enable /* r1+0x8 */) {
    // Local variables
    BOOL enabled; // r31
    BOOL prev; // r30

    // References
    // -> static void (* FatalFunc)();

    enabled = OSDisableInterrupts();
    prev = FatalFunc ? TRUE : FALSE;
    FatalFunc = enable ? ShowMessage : NULL;
    OSRestoreInterrupts(enabled);
    return prev;
}

// Range: 0x10C -> 0x140
void __DVDPrintFatalMessage(void) {
    // References
    // -> static void (* FatalFunc)();

    if (FatalFunc) {
        FatalFunc();
    }
}
