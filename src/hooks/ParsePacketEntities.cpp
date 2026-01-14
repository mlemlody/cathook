#include "common.hpp"
#include "DetourHook.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include "hooks/ClassIdTranslator.hpp"

// Hook CL_ParsePacketEntities (engine.so) to log state before parsing.
// Signature provided: "C7 04 24 ? ? ? ? E8"
// Disassembled target: sub_2B0650(int a1, int a2)

namespace hooks::packetentities
{
using Fn_t = int (*)(int, int);
static DetourHook g_detour;
// Keep translation disabled by default. Two env toggles exist:
//  - CATHOOK_DISABLE_CLASSID_TRANSLATION: legacy kill-switch if set (non-empty and not '0').
//  - CATHOOK_ENABLE_UNSAFE_PACKET_TRANSLATION: explicit opt-in to mutate packet data pre-parse.
static bool g_disable_legacy = [](){
    if (const char* v = std::getenv("CATHOOK_DISABLE_CLASSID_TRANSLATION"))
        return v[0] != '\0' && v[0] != '0';
    return false;
}();
static bool g_enable_unsafe = [](){
    // Default: ON. Disable with CATHOOK_DISABLE_UNSAFE_PACKET_TRANSLATION=1 or CATHOOK_ENABLE_UNSAFE_PACKET_TRANSLATION=0
    if (const char* vdis = std::getenv("CATHOOK_DISABLE_UNSAFE_PACKET_TRANSLATION")) {
        if (vdis[0] != '\0' && vdis[0] != '0') return false;
    }
    if (const char* ven = std::getenv("CATHOOK_ENABLE_UNSAFE_PACKET_TRANSLATION")) {
        return ven[0] != '\0' && ven[0] != '0';
    }
    return true;
}();

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
        // Basic plausibility guard: only read if a2 looks like a user-space pointer.
        uintptr_t base = static_cast<uintptr_t>(static_cast<uint32_t>(a2));
        if (base >= 0x10000u) {
            v_a2 = *reinterpret_cast<int *>(a2 + 20);
            v_a3 = *reinterpret_cast<int *>(a2 + 28);
            v_a4 = *reinterpret_cast<int *>(a2 + 16);
            v_a5 = *reinterpret_cast<int *>(a2 + 32);
            v_a6 = *reinterpret_cast<int *>(a2 + 40);
        } else {
            logging::Info("[CL_ParsePacketEntities] BEFORE: a2 pointer 0x%p not plausible, skipping field reads", (void*) (uintptr_t) a2);
        }
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
    // IMPORTANT: This is unsafe for engine baseline lookups and is disabled by default.
    if (g_enable_unsafe && !g_disable_legacy && hooks::classid::IsReady() && a2)
    {
        // Only touch memory if a2 looks like a plausible userspace pointer.
        uintptr_t a2_base = static_cast<uintptr_t>(static_cast<uint32_t>(a2));
        if (a2_base < 0x10000u)
        {
            logging::Info("[CL_ParsePacketEntities] Skipping translation: a2 pointer 0x%p not plausible", (void*) a2_base);
            // Proceed to call original below
        }
        else
        {
        // Try to auto-detect the classId field among common offsets seen in the logs/IDA
        // Candidates in bytes from base of second arg struct
        static const int kCandidates[] = { 16, 20, 24, 28, 32, 36, 40 };
        static int g_classIdOffset = -1; // memoized after detection
        static int g_confirmCounts[sizeof(kCandidates)/sizeof(kCandidates[0])] = {0};
        static bool g_logged_stabilized = false;

        auto validate_offset = [&](int off, int& sid_out, int& cid_out, std::string& name_out) -> bool {
            // Re-check plausibility inside validator as well.
            uintptr_t base = static_cast<uintptr_t>(static_cast<uint32_t>(a2));
            if (base < 0x10000u) return false;
            int* p = reinterpret_cast<int*>(a2 + off);
            if (!p) return false;
            int sid = *p;
            if (sid < 0 || sid > 4096) return false; // sanity
            auto name = hooks::classid::NameFromServerId(sid);
            if (name.empty()) return false;
            int cid = hooks::classid::TranslateServerToClient(sid);
            if (cid < 0 || cid > 4096) return false;
            // Strong round-trip check: client->server must map back to same sid and names must match
            if (hooks::classid::TranslateClientToServer(cid) != sid) return false;
            auto cname = hooks::classid::NameFromClientId(cid);
            if (cname != name) return false;
            sid_out = sid; cid_out = cid; name_out = std::move(name);
            return true;
        };

        if (g_classIdOffset >= 0)
        {
            int sid = -1, cid = -1; std::string nm;
            if (validate_offset(g_classIdOffset, sid, cid, nm) && cid != sid)
            {
                int* p = reinterpret_cast<int*>(a2 + g_classIdOffset);
                *p = cid;
                logging::Info("[CL_ParsePacketEntities] Translated class ID at +%d: %d (%s) -> %d", g_classIdOffset, sid, nm.c_str(), cid);
            }
        }
        else
        {
            // Detection phase: require multiple successful validations for the SAME offset
            int idx = 0;
            for (int off : kCandidates)
            {
                int sid = -1, cid = -1; std::string nm;
                if (validate_offset(off, sid, cid, nm))
                {
                    if (g_confirmCounts[idx] < 1000) ++g_confirmCounts[idx];
                    if (g_confirmCounts[idx] == 1)
                        logging::Info("[CL_ParsePacketEntities] Candidate class ID offset +%d looks valid (sid=%d name=%s -> cid=%d). Confirming...", off, sid, nm.c_str(), cid);
                    if (g_confirmCounts[idx] >= 3)
                    {
                        g_classIdOffset = off;
                        logging::Info("[CL_ParsePacketEntities] Confirmed class ID offset at +%d after %d samples", off, g_confirmCounts[idx]);
                        break;
                    }
                }
                ++idx;
            }
            if (g_classIdOffset >= 0 && !g_logged_stabilized)
            {
                g_logged_stabilized = true;
                logging::Info("[CL_ParsePacketEntities] Translation activated using offset +%d", g_classIdOffset);
            }
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

    if (g_disable_legacy)
        logging::Info("ParsePacketEntities: translation disabled via CATHOOK_DISABLE_CLASSID_TRANSLATION");
    if (g_enable_unsafe)
        logging::Info("ParsePacketEntities: UNSAFE packet classid translation is ON (disable with CATHOOK_DISABLE_UNSAFE_PACKET_TRANSLATION=1 or CATHOOK_ENABLE_UNSAFE_PACKET_TRANSLATION=0)");
    else
        logging::Info("ParsePacketEntities: UNSAFE packet classid translation is OFF (enable with CATHOOK_ENABLE_UNSAFE_PACKET_TRANSLATION=1)");

    hooks::classid::Init();

    EC::Register(EC::Shutdown, []() {
        g_detour.Shutdown();
    }, "parsepacketentities_shutdown");
});

} // namespace hooks::packetentities
