#include "common.hpp"
#include "hooks/ClassIdTranslator.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

namespace hooks::classid {

static std::once_flag g_once;
static std::unordered_map<int, std::string> g_serverIdToName; // x64
static std::unordered_map<int, std::string> g_clientIdToName; // x86
static std::unordered_map<std::string, int> g_serverNameToId;
static std::unordered_map<std::string, int> g_clientNameToId;
static bool g_ready = false;
static int g_dummyClientId = -1;
static const char* g_embeddedX64 = nullptr;
static const char* g_embeddedX32 = nullptr;

static bool parse_x32_line(const char* s, int& id, std::string& name) {
    // Format example: "[179] CTETFParticleEffect | DT_TETFParticleEffect"
    // Accept leading spaces; stop at " | "
    while (*s == ' ' || *s == '\t') ++s;
    if (*s != '[') return false;
    ++s; char* endptr = nullptr;
    long val = std::strtol(s, &endptr, 10);
    if (!endptr || *endptr != ']') return false;
    id = static_cast<int>(val);
    s = endptr + 1;
    while (*s == ' ' || *s == '\t') ++s;
    // name until " | " or end
    const char* bar = std::strstr(s, " | ");
    if (!bar) return false;
    name.assign(s, bar - s);
    return !name.empty();
}

static bool parse_x64_line(const char* s, int& id, std::string& name);

static void try_load_memory(const char* text, bool is_x64, int max_lines = 200000) {
    if (!text) return;
    const char* s = text;
    int line_no = 0;
    while (*s && line_no < max_lines) {
        const char* e = std::strchr(s, '\n');
        std::string line;
        if (e) { line.assign(s, e - s); s = e + 1; }
        else { line.assign(s); s += line.size(); }
        ++line_no;
        int id = -1; std::string name;
        bool ok = is_x64 ? parse_x64_line(line.c_str(), id, name) : parse_x32_line(line.c_str(), id, name);
        if (!ok) continue;
        if (is_x64) { g_serverIdToName[id] = name; g_serverNameToId[name] = id; }
        else { g_clientIdToName[id] = name; g_clientNameToId[name] = id; }
    }
}

static bool parse_x64_line(const char* s, int& id, std::string& name) {
    // Support either
    // 1) Bracket format: "[179] CSomeClass | DT_SomeTable"
    // 2) Verbose format: "... ID=351 Name=CSomeClass RecvTable=..."
    if (!s) return false;
    // Skip leading spaces
    while (*s == ' ' || *s == '\t') ++s;
    // Prefer ID=/Name= format anywhere on the line (handles prefixes like "[AFTER]")
    const char* idp = std::strstr(s, "ID=");
    const char* namep = std::strstr(s, "Name=");
    if (idp && namep) {
        idp += 3; char* endptr = nullptr;
        long val = std::strtol(idp, &endptr, 10);
        if (endptr == idp) return false;
        id = static_cast<int>(val);
        namep += 5;
        // name until space or end; but names have no spaces
        const char* sp = namep;
        while (*sp && *sp != ' ' && *sp != '\r' && *sp != '\n' && *sp != '\t') ++sp;
        name.assign(namep, sp - namep);
        return !name.empty();
    }
    // Fallback: bracketed format at start of line
    if (*s == '[') {
        return parse_x32_line(s, id, name);
    }
    return false;
}

static void try_load_file(const char* path, bool is_x64, int max_lines = 200000) {
    if (!path) return;
    size_t before = is_x64 ? g_serverIdToName.size() : g_clientIdToName.size();
    if (FILE* f = std::fopen(path, "rb")) {
        char line[2048];
        int line_no = 0;
        while (std::fgets(line, sizeof(line), f)) {
            if (++line_no > max_lines) break;
            int id = -1; std::string name;
            bool ok = is_x64 ? parse_x64_line(line, id, name) : parse_x32_line(line, id, name);
            if (!ok) continue;
            if (is_x64) {
                g_serverIdToName[id] = name;
                g_serverNameToId[name] = id;
            } else {
                g_clientIdToName[id] = name;
                g_clientNameToId[name] = id;
            }
        }
        std::fclose(f);
        size_t after = is_x64 ? g_serverIdToName.size() : g_clientIdToName.size();
        size_t added = after >= before ? (after - before) : 0;
        logging::Info("ClassIdTranslator: parsed %zu %s entries from '%s'", added, is_x64?"server(x64)":"client(x86)", path);
    } else {
        logging::Info("ClassIdTranslator: failed to open '%s'", path);
    }
}

static std::vector<std::string> candidate_paths(const char* fname) {
    // Try common run-from-repo and run-from-install layouts
    std::vector<std::string> paths;
    paths.emplace_back(std::string("src/hooks/txt/") + fname);
    paths.emplace_back(std::string("./src/hooks/txt/") + fname);
    paths.emplace_back(std::string("../src/hooks/txt/") + fname);
    // System-wide install location for client fix dumps
    paths.emplace_back(std::string("/opt/cathook/clientfix/") + fname);
    // Allow override via env var CATHOOK_TXT_DIR
    if (const char* dir = std::getenv("CATHOOK_TXT_DIR")) {
        std::string p = dir; if (!p.empty() && p.back() != '/' && p.back() != '\\') p.push_back('/');
        p += fname; paths.emplace_back(std::move(p));
    }
    return paths;
}

void Init() {
    std::call_once(g_once, [](){
        // Prefer embedded text if provided
        if (g_embeddedX64) try_load_memory(g_embeddedX64, /*is_x64=*/true);
        if (g_embeddedX32) try_load_memory(g_embeddedX32, /*is_x64=*/false);
        // Fallback to filesystem if any map is still empty
        if (g_serverIdToName.empty()) {
            for (const auto& p : candidate_paths("x64parseclassinfo")) {
                logging::Info("ClassIdTranslator: trying server dump path: %s", p.c_str());
                try_load_file(p.c_str(), /*is_x64=*/true);
                if (!g_serverIdToName.empty()) break;
            }
        }
        if (g_clientIdToName.empty()) {
            for (const auto& p : candidate_paths("x32parseclassinfo")) {
                logging::Info("ClassIdTranslator: trying client dump path: %s", p.c_str());
                try_load_file(p.c_str(), /*is_x64=*/false);
                if (!g_clientIdToName.empty()) break;
            }
        }
        g_ready = !g_serverIdToName.empty() && !g_clientIdToName.empty();
        // compute dummy client id once
        if (!g_clientNameToId.empty()) {
            auto it = g_clientNameToId.find("CBaseEntity");
            if (it != g_clientNameToId.end()) {
                g_dummyClientId = it->second;
            } else {
                // choose the smallest ID as safest fallback
                int minId = INT32_MAX;
                for (const auto& kv : g_clientIdToName) minId = std::min(minId, kv.first);
                if (minId != INT32_MAX) g_dummyClientId = minId;
            }
        }
        logging::Info("ClassIdTranslator: loaded %zu server classes and %zu client classes%s",
                      g_serverIdToName.size(), g_clientIdToName.size(), g_ready?"":" (incomplete)");
    });
}

bool IsReady() { return g_ready; }

int TranslateServerToClient(int serverId) {
    auto it = g_serverIdToName.find(serverId);
    if (it == g_serverIdToName.end()) return serverId;
    const std::string& name = it->second;
    auto jt = g_clientNameToId.find(name);
    if (jt == g_clientNameToId.end()) return serverId;
    return jt->second;
}

int TranslateClientToServer(int clientId) {
    auto it = g_clientIdToName.find(clientId);
    if (it == g_clientIdToName.end()) return clientId;
    const std::string& name = it->second;
    auto jt = g_serverNameToId.find(name);
    if (jt == g_serverNameToId.end()) return clientId;
    return jt->second;
}

std::string NameFromServerId(int serverId) {
    auto it = g_serverIdToName.find(serverId);
    return it == g_serverIdToName.end() ? std::string() : it->second;
}

std::string NameFromClientId(int clientId) {
    auto it = g_clientIdToName.find(clientId);
    return it == g_clientIdToName.end() ? std::string() : it->second;
}

const std::unordered_map<int, std::string>& GetServerIdToName() { return g_serverIdToName; }
const std::unordered_map<int, std::string>& GetClientIdToName() { return g_clientIdToName; }

int GetDummyClientId() { return g_dummyClientId; }

int ClientIdFromName(const std::string& name) {
    auto it = g_clientNameToId.find(name);
    if (it == g_clientNameToId.end()) return -1;
    return it->second;
}

int ServerIdFromName(const std::string& name) {
    auto it = g_serverNameToId.find(name);
    if (it == g_serverNameToId.end()) return -1;
    return it->second;
}

void SetEmbeddedDumps(const char* x64_text, const char* x32_text) {
    g_embeddedX64 = x64_text;
    g_embeddedX32 = x32_text;
}

} // namespace hooks::classid
