#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace hooks::classid
{
// Initialize by parsing dumps under src/hooks/txt/{x32parseclassinfo,x64parseclassinfo}.
// Safe to call multiple times; it will no-op after success.
void Init();

// Returns true if initialization parsed both maps.
bool IsReady();

// Translate server (x64) class ID -> client (x86) class ID using class name.
// If no mapping is found, returns the input id.
int TranslateServerToClient(int serverId);

// Translate client (x86) class ID -> server (x64) class ID using class name.
// If no mapping is found, returns the input id.
int TranslateClientToServer(int clientId);

// Lookup helpers. Empty if not found.
std::string NameFromServerId(int serverId);
std::string NameFromClientId(int clientId);
int ClientIdFromName(const std::string& name);

// For diagnostics
const std::unordered_map<int, std::string>& GetServerIdToName();
const std::unordered_map<int, std::string>& GetClientIdToName();

// Fallback: a safe, "do-nothing" client class ID (e.g., CBaseEntity if present).
// Returns -1 if not available.
int GetDummyClientId();

} // namespace hooks::classid
