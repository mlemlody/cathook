#include "common.hpp"
#include "DetourHook.hpp"
#include <cstdio>
#include <cstdint>
#include "hooks/ClassIdTranslator.hpp"

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

    // Translate class ID from server (x64) -> client (x86) before game processes packet
    if (hooks::classid::IsReady() && a2)
    {
        // Try to auto-detect the classId field among common offsets seen in the logs/IDA
        // Candidates in bytes from base of second arg struct
        static const int kCandidates[] = { 16, 20, 24, 28, 32, 36, 40 };
        static int g_classIdOffset = -1; // memoized after detection

        auto try_translate_at = [&](int off) -> bool {
            int* p = reinterpret_cast<int*>(a2 + off);
            if (!p) return false;
            int sid = *p;
            if (sid < 0 || sid > 4096) return false; // sanity
            // must resolve to a valid server name and a valid client id by name
            auto name = hooks::classid::NameFromServerId(sid);
            int cid = hooks::classid::TranslateServerToClient(sid);
            if (!name.empty() && cid != sid)
            {
                *p = cid;
                logging::Info("[CL_ParsePacketEntities] Translated class ID at +%d: %d (%s) -> %d", off, sid, name.c_str(), cid);
                return true;
            }
            return false;
        };

        if (g_classIdOffset >= 0)
        {
            (void)try_translate_at(g_classIdOffset);
        }
        else
        {
            for (int off : kCandidates)
            {
                if (try_translate_at(off)) { g_classIdOffset = off; break; }
            }
        }
    }

    // Call original and restore patch
    Fn_t orig = (Fn_t) g_detour.GetOriginalFunc();
    int ret   = orig ? orig(a1, a2) : 0;
    g_detour.RestorePatch();
    return ret;
}

static InitRoutine init([]() {
    // Engine function signature (AOB) to locate CL_ParsePacketEntities entry (prologue pattern).
    static uintptr_t site = gSignatures.GetEngineSignature(
        "55 89 E5 57 56 53 83 EC ? C7 45 ? ? ? ? ? A1 ? ? ? ? C7 45 ? ? ? ? ? 8B 75 ? 8B 5D ? 85 C0 0F 84 ? ? ? ? 8D 55 ? 89 04 24 89 54 24 ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? FF 50 ? A1 ? ? ? ? 8B 55 ? 89 45 ? 8B 45 ? 89 55 ? 89 45 ? A1 ? ? ? ? 85 C0 0F 85 ? ? ? ? 8B 4B ? C6 45 ? ? 85 C9 0F 84 ? ? ? ? 8B 43 ? 8D 50 ? 81 FA ? ? ? ? 0F 8F ? ? ? ? 89 D0 83 E2 ? C1 F8 ? 8D 3C 85 ? ? ? ? 89 45 ? 8D 4C 39 ? 8B 01 29 F9 23 04 95 ? ? ? ? 89 C2 75 ? 8B 45 ? 8D B4 26 ? ? ? ? 83 C0 ? 83 F8 ? 0F 84 ? ? ? ? 8B 14 81 85 D2 74 ? 89 45 ? 8B 45 ? 0F B6 CA C1 E0 ? 85 C9"
    );
    if (!site)
    {
        logging::Info("ParsePacketEntities: engine signature not found; hook disabled");
        return;
    }
    uintptr_t addr = site;

    g_detour.Init(addr, (void *) hook_impl);
    logging::Info("ParsePacketEntities: hook installed at 0x%p", (void *) addr);

    hooks::classid::Init();

    EC::Register(EC::Shutdown, []() {
        g_detour.Shutdown();
    }, "parsepacketentities_shutdown");
});

} // namespace hooks::packetentities
