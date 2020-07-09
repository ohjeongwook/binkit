#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "Function.h"
#include "BasicBlocks.h"

using namespace std;
using namespace stdext;

class Functions
{
private:
    DisassemblyReader* m_pdisassemblyReader;
    BasicBlocks* m_pbasicBlocks;

    multimap<va_t, va_t> m_basicBlockToFunctionAddresses;
    vector<Function *> m_functions;
    multimap<va_t, Function*> m_addressToFunctions;

    void Load();
    bool UpdateFunctionAddressesInStorage();
public:
    Functions(DisassemblyReader* p_disassemblyReader = NULL, BasicBlocks *p_basicBlocks = NULL);
    ~Functions();

    vector<Function*>* GetFunctions();
    Function* GetFunction(va_t address);
    bool IsInFunction(va_t basicBlockAddress, va_t functionAddress);
};