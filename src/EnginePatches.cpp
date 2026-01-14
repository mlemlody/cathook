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

    static BytePatch patch_copyentityy(gSignatures.GetEngineSignature, "0F 84 ? ? ? ? A1 ? ? ? ? 8B 78 ? 85 FF 74 ? C7 04 24", 0x0, { 0xE9, 0xE6, 0xFE, 0xFF });
    patch_copyentityy.Patch();

    static BytePatch patchez (gSignatures.GetEngineSignature, "74 ? 8B 03 89 1C 24 C7 44 24 ? ? ? ? ? FF 50 ? 83 C4", 0x0, { 0xEB  });
    patchez.Patch();

    static BytePatch patch2(gSignatures.GetEngineSignature, "E8 ? ? ? ? 8B 45 ? 83 C4 ? 5B 5E 5F 5D C3 EB", 0x0, { 0xB8, 0xD3, 0x4B, 0x70, 0x20, 0x90, 0x90, 0x90 });
    patch2.Patch();
    
    static BytePatch patch_copyentity(gSignatures.GetEngineSignature, "0F 84 ? ? ? ? 8B 45 ? 85 C0 0F 84 ? ? ? ? 8B 10", 0x0, { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
    patch_copyentity.Patch();
    
    static BytePatch patch_entity_error(gSignatures.GetEngineSignature, "68 ? ? ? ? E8 ? ? ? ? 83 C4 ? 5B 5E 5F 5D C3", 0x0, { 0x83, 0xC4, 0x04, 0x5B, 0x5E, 0x5F, 0x5D, 0xC3 });
    patch_entity_error.Patch();
    
    static BytePatch patch_entity_check(gSignatures.GetEngineSignature, "74 ? 8B 40 ? 85 C0 74 ? 8B 10 8B 52", 0x0, { 0xEB });
    patch_entity_check.Patch();
    
    
    unsigned int crc = 544230355;
    uintptr_t g_SendTableCRC_ptrptr = gSignatures.GetEngineSignature("C7 05 ? ? ? ? ? ? ? ? A3 ? ? ? ? 83 C4") + 0x2;

    BytePatch::mprotectAddr(g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);
    BytePatch::mprotectAddr(*(uintptr_t *) g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);
    BytePatch::mprotectAddr(**(uintptr_t **) g_SendTableCRC_ptrptr, 4, PROT_READ | PROT_WRITE | PROT_EXEC);

    unsigned int *g_SendTableCRC_ptr = *((unsigned int **) g_SendTableCRC_ptrptr);
    *g_SendTableCRC_ptr      = crc;
}); 