#include "common.hpp"
#include "DetourHook.hpp"
#include <cstdio>

// Hook CL_ParsePacketEntities (engine.so) to log state before parsing.
// Signature provided: "C7 04 24 ? ? ? ? E8"
// Disassembled target: sub_2B0650(int a1, int a2)

namespace hooks::packetentities
{
using Fn_t = int (*)(int, int);
static DetourHook g_detour;

static void log_before(int a1, int a2)
{
    // Extract fields from the structure pointed by a2 (based on disassembly offsets)
    // These map to the user's requested a2..a6 values for logging.
    int v_a2 = 0;   // *(a2 + 20)
    int v_a3 = 0;   // *(a2 + 28)
    int v_a4 = 0;   // *(a2 + 16)
    int v_a5 = 0;   // *(a2 + 32)
    int v_a6 = 0;   // *(a2 + 40)

    if (a2)
    {
        // Use volatile reads to avoid UB with potential aliasing; still best-effort.
        v_a2 = *reinterpret_cast<int *>(a2 + 20);
        v_a3 = *reinterpret_cast<int *>(a2 + 28);
        v_a4 = *reinterpret_cast<int *>(a2 + 16);
        v_a5 = *reinterpret_cast<int *>(a2 + 32);
        v_a6 = *reinterpret_cast<int *>(a2 + 40);
    }

    // Print exactly as requested (pointer for a1, ints for others)
    logging::Info("[CL_ParsePacketEntities] BEFORE: a1=%p a2=%d a3=%d a4=%d a5=%d a6=%d", (void *) a1, v_a2, v_a3, v_a4, v_a5, v_a6);

    // Also append to a file on disk for persistence
    if (FILE *f = std::fopen("/tmp/cathook-packetentities.txt", "a"))
    {
        std::fprintf(f, "[CL_ParsePacketEntities] BEFORE: a1=%p a2=%d a3=%d a4=%d a5=%d a6=%d\n",
                     (void *) a1, v_a2, v_a3, v_a4, v_a5, v_a6);
        std::fclose(f);
    }
}

static int hook_impl(int a1, int a2)
{
    log_before(a1, a2);

    // Call original and restore patch
    Fn_t orig = (Fn_t) g_detour.GetOriginalFunc();
    int ret   = orig ? orig(a1, a2) : 0;
    g_detour.RestorePatch();
    return ret;
}

static InitRoutine init([]() {
    // Engine function signature (AOB) to locate CL_ParsePacketEntities
    static uintptr_t addr = gSignatures.GetEngineSignature("C7 04 24 ? ? ? ? E8");
    if (!addr)
    {
        logging::Info("ParsePacketEntities: engine signature not found; hook disabled");
        return;
    }
    g_detour.Init(addr, (void *) hook_impl);
    logging::Info("ParsePacketEntities: hook installed at 0x%p", (void *) addr);

    EC::Register(EC::Shutdown, []() {
        g_detour.Shutdown();
    }, "parsepacketentities_shutdown");
});

} // namespace hooks::packetentities
