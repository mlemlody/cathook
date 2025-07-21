#include "DetourHook.hpp"
#include "copypasted/CSignature.h"
#include "hooks/HookTools.hpp"
#include "init.hpp"
#include "core/logging.hpp"
#include <cstdarg>
static DetourHook host_error_detour;

extern "C" void __attribute__((cdecl)) Host_Error_hook(const char *pInMessage, ...)
{
    logging::Info("Suppressed Host_Error: %s", pInMessage ? pInMessage : "(null)");
}

static InitRoutine host_error_init([]() {
    uintptr_t host_error_addr = gSignatures.GetEngineSignature("55 89 E5 53 81 EC 24 04 00 00");
    if (!host_error_addr)
    {
        logging::Info("Host_Error signature not found – skipping detour");
        return;
    }

    host_error_detour.Init(host_error_addr, (void *) Host_Error_hook);

    EC::Register(EC::Shutdown, []() { host_error_detour.Shutdown(); }, "host_error_detour_shutdown");
}); 