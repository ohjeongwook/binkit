#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"

using namespace std;
using namespace stdext;

class BasicBlocks
{
private:
    DisassemblyReader* m_pdisassemblyReader;
    DisassemblyHashMaps m_disassemblyHashMaps;

    void MergeBlocks();
    void RemoveFromInstructionHashHash(va_t address);
public:
    BasicBlocks(DisassemblyReader* p_disassemblyReader = NULL, bool load = false);
    ~BasicBlocks();

    void Load(va_t functionAddress = 0);
    vector<va_t> GetAddresses();
    va_t GetBasicBlockStart(va_t address);
    PBasicBlock GetBasicBlock(va_t address);
    string GetSymbol(va_t address);
    string GetDisasmLines(unsigned long startAddress, unsigned long endAddress);
    vector<va_t> GetCodeReferences(va_t address, int type);
    vector<va_t> GetParents(va_t address);
    vector<va_t> GetCallTargets();
    InstructionHashMap *GetInstructionHashes();

    vector<va_t> GetInstructionHashMatches(vector<unsigned char> instructionHash);
    vector<unsigned char> GetInstructionHash(va_t address);
    vector<unsigned char> GetInstructionBytes(va_t address);

    void GenerateTwoLevelInstructionHash();
    void DumpBlockInfo(va_t blockAddress);
};