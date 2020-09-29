#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "BasicBlocks.h"
#include "Function.h"

using namespace std;
using namespace stdext;

class Binary
{
private:
    int m_fileId;
    BasicBlocks* m_pbasicBlocks;

    DisassemblyReader* m_pdisassemblyReader;
    multimap<va_t, va_t> m_basicBlockToFunctionAddresses;
    vector<Function*> m_functions;
    multimap<va_t, Function*> m_functionAddressMap;

    void LoadFunctionAddressMap();
    void LoadBasicBlockToFunctionMap();
    bool UpdateFunctionAddressesInStorage();

public:
    Binary(string databaseFileName = {}, int fileID = 0);
    ~Binary();
    void Open(string databaseFileName, int fileId = 0);
    int GetFileID();
    string GetMD5();
    unsigned long long GetImageBase();

    BasicBlocks* GetBasicBlocks();
    vector<Function*>* GetFunctions();
    vector<Function*> GetFunction(va_t address);
    Function *GetFunctionByStartAddress(va_t address);
    bool IsInFunction(va_t basicBlockAddress, va_t functionAddress);
};
