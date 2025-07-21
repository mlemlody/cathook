#include "bytepatch.hpp"
#include "copypasted/CSignature.h"
#include "init.hpp"
#include <sys/mman.h>

/*
 * EnginePatches.cpp
 *
 * Centralizes various one-off engine patches that were previously in hack.cpp.
 */

static InitRoutine engine_patches_init([]() {
    
    unsigned int crc = 544230355;
    uintptr_t g_SendTableCRC_ptrptr = gSignatures.GetEngineSignature("C7 05 ? ? ? ? ? ? ? ? A3 ? ? ? ? 83 C4") + 0x2;

    BytePatch::mprotectAddr(g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);
    BytePatch::mprotectAddr(*(uintptr_t *) g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);
    BytePatch::mprotectAddr(**(uintptr_t **) g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);

    unsigned int *g_SendTableCRC_ptr = *((unsigned int **) g_SendTableCRC_ptrptr);
    *g_SendTableCRC_ptr      = crc;
}); 