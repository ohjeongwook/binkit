#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <list>

#include "Structures.h"
#include "InstructionHash.h"
#include "DisassemblyReader.h"

using namespace std;
using namespace stdext;

class BasicBlocks
{
private:
    DisassemblyReader* m_pdisassemblyReader;
    DisassemblyHashMaps m_disassemblyHashMaps;
    multimap <va_t, PControlFlow> m_addressToControlFlowMap;
    multimap <va_t, va_t> m_dstToSrcAddressMap;

    void LoadData(va_t functionAddress = 0);
    void MergeBlocks();
public:
    BasicBlocks(DisassemblyReader* p_disassemblyReader = NULL, bool load = false);
    ~BasicBlocks();

    vector<va_t> GetAddresses();

    PBasicBlock GetBasicBlock(va_t address);
    va_t GetStartAddress(va_t address);    
    va_t GetEndAddress(va_t address);
    string GetSymbol(va_t address);
    string GetDisasmLines(unsigned long startAddress);
    vector<va_t> GetCodeReferences(va_t address, int type);
    vector<va_t> GetParents(va_t address);
    vector<va_t> GetCallTargets();
    InstructionHashMap *GetInstructionHashes();

    vector<unsigned char> GetInstructionBytes(va_t address);
    void DumpBlockInfo(va_t blockAddress);
};