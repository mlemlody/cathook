#include "common.hpp"
#include "hooks/ClassIdTranslator.hpp"

// Auto-generated at configure time by CMake from src/hooks/txt/x32parseclassinfo and x64parseclassinfo
// Embeds the dump text directly in the binary to avoid runtime file dependency.

namespace {
static const char* kEmbeddedX64 = R"EMBED_X64(@X64_CONTENT@)EMBED_X64";
static const char* kEmbeddedX32 = R"EMBED_X32(@X32_CONTENT@)EMBED_X32";

struct _EmbedInit {
    _EmbedInit() {
        hooks::classid::SetEmbeddedDumps(kEmbeddedX64, kEmbeddedX32);
    }
} _embedInit;
}
