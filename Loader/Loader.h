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

class Loader
{
private:
    int m_fileID;
    string Identity;
    string m_originalFilePath;

    DisassemblyReader *m_pdisassemblyReader;
    DisassemblyHashMaps m_disassemblyHashMaps;
    
    multimap <va_t, va_t> m_blockToFunction;
    multimap <va_t, va_t> m_functionToBlock;
    unordered_set <va_t> m_functionHeads;

    BOOL LoadBasicBlock(va_t functionAddress = 0);
    void LoadControlFlow(multimap <va_t, PControlFlow> *p_controlFlow, va_t address, bool IsFunction = false);    
    void RemoveFromInstructionHashHash(va_t address);

    vector <va_t> *GetFunctionAddresses();
    void GenerateTwoLevelInstructionHash();
    void MergeBlocks();

public:
    Loader(DisassemblyReader *DisassemblyReader = NULL);
    ~Loader();
    BOOL Load(va_t functionAddress = 0);
    void LoadBlockFunctionMaps();

    void SetFileID(int FileID = 1);
    int GetFileID();
    string GetIdentity();
    string GetOriginalFilePath();

    va_t GetBasicBlockStart(va_t address);
    PBasicBlock GetBasicBlock(va_t address);
    vector<va_t> *GetCodeReferences(va_t address, int type);
    char *GetSymbol(va_t address);    
    char *GetDisasmLines(unsigned long startAddress, unsigned long endAddress);
    char *GetInstructionHashStr(va_t address);

    void ClearBlockFunctionMaps();
    BOOL FixFunctionAddresses();
    bool GetFunctionAddress(va_t address, va_t& functionAddress);
    bool IsFunctionBlock(va_t block, va_t function);
    list <AddressRange> GetFunctionBasicBlocks(unsigned long FunctionAddress);
    multimap <va_t, va_t> *GetFunctionToBlock();

    void DumpDisassemblyHashMaps();
    void DumpBlockInfo(va_t blockAddress);
};
