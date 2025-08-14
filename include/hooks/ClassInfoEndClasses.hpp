#pragma once

#include <string>
#include <vector>
#include <unordered_map>

// Provides access to the cached client class snapshot captured around
// CL_ParseClassInfo_EndClasses() execution.
namespace hooks::classinfo
{
struct ClientClassInfo
{
    int id{ -1 };
    std::string name;        // Client class name (ClientClass::GetName())
    std::string recvtable;   // RecvTable::GetName()
};

// Returns the latest captured snapshot (after original function return).
const std::vector<ClientClassInfo> &GetClientClasses();

// Name -> ID mapping from the latest snapshot.
const std::unordered_map<std::string, int> &GetNameToId();
}
