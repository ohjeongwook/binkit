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
    char* m_OriginalFilePath;
    multimap <va_t, va_t> m_codeReferenceMap;
    multimap <va_t, va_t> m_blockToFunction;
    multimap <va_t, va_t> m_functionToBlock;
    unordered_set <va_t> m_functionHeads;

    DisassemblyReader *m_pdisassemblyReader;
    DisassemblyHashMaps m_disassemblyHashMaps;

    void LoadMapInfo(multimap <va_t, PMapInfo> *p_mapInfo, va_t address, bool IsFunction = false);
    BOOL LoadBasicBlock(va_t functionAddress = 0);
    void BuildCodeReferenceMap(multimap <va_t, PMapInfo> *p_mapInfo);

    void GenerateTwoLevelInstructionHash();
    void MergeBlocks();

public:
    Loader(DisassemblyReader *DisassemblyReader = NULL);
    ~Loader();
    void SetFileID(int FileID = 1);
    int GetFileID();
    string GetIdentity();
    char *GetOriginalFilePath();

    BOOL Load(va_t functionAddress = 0);

    PBasicBlock GetBasicBlock(va_t address);
    list <va_t> *GetFunctionAddresses();
    multimap <va_t, va_t> *GetFunctionToBlock();

    char *GetSymbol(va_t address);
    char *GetInstructionHashStr(va_t address);

    void DumpDisassemblyHashMaps();
    void DumpBlockInfo(va_t blockAddress);
    void RemoveFromInstructionHashHash(va_t address);

    va_t GetBlockAddress(va_t address);
    va_t *GetMappedAddresses(va_t address, int type, int *p_length);
    char *GetDisasmLines(unsigned long startAddress, unsigned long endAddress);

    void LoadBlockToFunction();
    void ClearBlockToFunction();
    BOOL FixFunctionAddresses();
    bool GetFunctionAddress(va_t address, va_t& functionAddress);
    bool IsFunctionBlock(va_t block, va_t function);
    list <AddressRange> GetFunctionMemberBlocks(unsigned long FunctionAddress);
};
