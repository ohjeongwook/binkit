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
    int m_FileID;
    string Identity;
    char* m_OriginalFilePath;
    va_t TargetFunctionAddress;
    multimap <va_t, va_t> m_codeReferenceMap;
    multimap <va_t, va_t> m_blockToFunction;
    multimap <va_t, va_t> m_functionToBlock;
    unordered_set <va_t> m_functionHeads;

    DisassemblyReader *m_pdisassemblyReader;
    DisassemblyHashMaps m_disassemblyHashMaps;

    void LoadMapInfo(multimap <va_t, PMapInfo> *p_map_info_map, va_t Address, bool IsFunction = false);
    BOOL LoadBasicBlock();
    void BuildCodeReferenceMap(multimap <va_t, PMapInfo> *p_map_info_map);

    void GenerateTwoLevelInstructionHash();
    void MergeBlocks();

public:
    Loader(DisassemblyReader *DisassemblyReader = NULL);
    ~Loader();
    void SetFileID(int FileID = 1);
    int GetFileID();
    string GetIdentity();
    char *GetOriginalFilePath();

    void AddAnalysisTargetFunction(va_t FunctionAddress);

    BOOL Load();

    multimap <va_t, va_t> *GetFunctionToBlock();
    PBasicBlock GetBasicBlock(va_t address);
    
    char *GetSymbol(va_t address);
    char *GetInstructionHashStr(va_t address);

    void DumpDisassemblyHashMaps();
    void DumpBlockInfo(va_t block_address);
    void RemoveFromInstructionHashHash(va_t address);

    va_t GetBlockAddress(va_t address);
    va_t *GetMappedAddresses(va_t address, int type, int *p_length);
    char *GetDisasmLines(unsigned long start_addr, unsigned long end_addr);

    void LoadBlockToFunction();
    void ClearBlockToFunction();
    BOOL FixFunctionAddresses();
    bool GetFunctionAddress(va_t address, va_t& function_address);
    bool FindBlockFunctionMatch(va_t block, va_t function);

    list <va_t> *GetFunctionAddresses();

    list <BLOCK> GetFunctionMemberBlocks(unsigned long FunctionAddress);
};
