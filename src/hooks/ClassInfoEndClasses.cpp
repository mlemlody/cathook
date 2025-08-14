#include "common.hpp"
#include "DetourHook.hpp"
#include "hooks/ClassInfoEndClasses.hpp"

#include <mutex>
#include <cstdio>

namespace hooks::classinfo
{

static std::vector<ClientClassInfo> g_latest;
static std::unordered_map<std::string, int> g_name_to_id;
static std::mutex g_mutex;
static DetourHook g_detour;

using Target_t = int (*)(int);

static void snapshot_classes(std::vector<ClientClassInfo> &out)
{
    out.clear();
    if (!g_IBaseClient)
        return;
    for (auto cc = g_IBaseClient->GetAllClasses(); cc; cc = cc->m_pNext)
    {
        ClientClassInfo info{};
        info.id       = cc->m_ClassID;
        info.name     = cc->GetName() ? cc->GetName() : "";
        info.recvtable = (cc->m_pRecvTable && cc->m_pRecvTable->GetName()) ? cc->m_pRecvTable->GetName() : "";
        out.emplace_back(std::move(info));
    }
}

static void write_dump(const char *phase, const std::vector<ClientClassInfo> &list)
{
    // Single file with two sections appended
    FILE *f = std::fopen("/tmp/cathook-classdump.txt", "a");
    if (!f)
        return;
    std::fprintf(f, "==== %s ====%s", phase, "\n");
    for (const auto &c : list)
        std::fprintf(f, "[%d] %s | %s%s", c.id, c.name.c_str(), c.recvtable.c_str(), "\n");
    std::fprintf(f, "\n");
    std::fclose(f);
}

static int hook_impl(int a1)
{
    // Take pre snapshot and write
    std::vector<ClientClassInfo> before;
    snapshot_classes(before);
    write_dump("Before CL_ParseClassInfo_EndClasses", before);

    // Call original
    Target_t orig = (Target_t) g_detour.GetOriginalFunc();
    int ret       = orig ? orig(a1) : 0;
    g_detour.RestorePatch();

    // Take post snapshot, publish, and write
    std::vector<ClientClassInfo> after;
    snapshot_classes(after);

    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_latest.swap(after);
        g_name_to_id.clear();
        for (const auto &c : g_latest)
            g_name_to_id.emplace(c.name, c.id);
    }

    write_dump("After CL_ParseClassInfo_EndClasses", g_latest);

    return ret;
}

const std::vector<ClientClassInfo> &GetClientClasses()
{
    return g_latest;
}

const std::unordered_map<std::string, int> &GetNameToId()
{
    return g_name_to_id;
}

static InitRoutine init([]() {
    // NOTE: This function resides in engine.so. The signature below targets
    // CL_ParseClassInfo_EndClasses(int a1) entry.
    static uintptr_t addr = 0;
    addr = gSignatures.GetEngineSignature(
        "55 89 E5 57 56 31 F6 53 83 EC ? 8B 7D ? 8B 87 ? ? ? ? 85 C0 7F ? E9 ? ? ? ? 8D 76 ? 8B 40 ? 8B 53 ? 8B 48 ? 89 14 24 89 55 ? 89 4C 24 ? 89 4D ? E8 ? ? ? ? 8B 55 ? 85 C0 8B 4D ? 75 ? 8B 03 89 70 ? 83 C6 ? 39 B7 ? ? ? ? 7E ? 89 F3 C1 E3 ? 03 9F ? ? ? ? 8B 43 ? 85 C0 74 ? 8B 43 ? 89 04 24 E8 ? ? ? ? 85 C0 89 03 75 ? 8B 43 ? 83 C6 ? C7 04 24 ? ? ? ? 89 44 24 ? E8 ? ? ? ? 39 B7 ? ? ? ? 7F ? 8D 76 ? 8D BC 27 ? ? ? ? 83 C4 ? B8 ? ? ? ? 5B 5E 5F 5D C3 8D 76 ? 89 4C 24 ? 89 54 24 ? 8B 43 ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? 89 44 24 ? E8 ? ? ? ? 83 C4 ? 31 C0 5B 5E 5F 5D C3"
    );

    if (!addr)
    {
        logging::Info("ClassInfoEndClasses: engine signature not found; hook disabled");
        return;
    }

    g_detour.Init(addr, (void *) hook_impl);
    logging::Info("ClassInfoEndClasses: hook installed at 0x%p", (void *) addr);

    EC::Register(EC::Shutdown, []() {
        g_detour.Shutdown();
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            g_latest.clear();
            g_name_to_id.clear();
        }
    }, "classinfo_endclasses_shutdown");
});

} // namespace hooks::classinfo
