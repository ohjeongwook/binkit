#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "BasicBlocks.h"

using namespace std;
using namespace stdext;

class Functions
{
private:
    DisassemblyReader* m_pdisassemblyReader;
    BasicBlocks* m_pbasicBlocks;

    multimap <va_t, va_t> m_blockToFunction;
    multimap <va_t, va_t> m_functionToBlock;
    unordered_set <va_t> m_functionAddresses;

    void Load();
    BOOL UpdateFunctionAddressesInStorage();
public:
    Functions(DisassemblyReader* p_disassemblyReader = NULL, BasicBlocks *p_basicBlocks = NULL);
    ~Functions();

    vector<va_t> *GetAddresses();
    vector <va_t> GetFunctionBasicBlocks(va_t FunctionAddress);
    bool GetFunctionAddress(va_t address, va_t& functionAddress);
    bool IsInFunction(va_t block, va_t function);
    multimap <va_t, va_t>* GetFunctionToBlock();
};