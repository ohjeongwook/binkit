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
    DisassemblyHashMaps *m_disassemblyHashMaps;

    void LoadMapInfo(multimap <va_t, PMapInfo> *p_map_info_map, va_t Address, bool IsFunction = false);
    void GenerateTwoLevelInstructionHash();
    void MergeBlocks();

public:
    Loader(DisassemblyReader *DisassemblyReader = NULL);
    ~Loader();
    void SetFileID(int FileID = 1);
    int GetFileID();
    string GetIdentity();

    BOOL Retrieve(char *DataFile, DWORD Offset = 0L, DWORD Length = 0L);
    BOOL Load();
    void AddAnalysisTargetFunction(va_t FunctionAddress);
    BOOL LoadBasicBlock();
    BOOL Save(char *DataFile, DWORD Offset = 0L, DWORD dwMoveMethod = FILE_BEGIN, unordered_set <va_t> *pSelectedAddresses = NULL);
    void DumpDisassemblyHashMaps();
    char *GetName(va_t address);
    void DumpBlockInfo(va_t block_address);
    char *GetInstructionHashStr(va_t address);
    void RemoveFromInstructionHashHash(va_t address);
    va_t GetBlockAddress(va_t address);
    va_t *GetMappedAddresses(va_t address, int type, int *p_length);
    char *GetDisasmLines(unsigned long start_addr, unsigned long end_addr);
    void Buildm_codeReferenceMap(multimap <va_t, PMapInfo> *p_map_info_map);

    void LoadBlockToFunction();
    multimap <va_t, va_t> *GetFunctionToBlock();
    PBasicBlock GetBasicBlock(va_t address);
    list <BLOCK> GetFunctionMemberBlocks(unsigned long FunctionAddress);
    char *GetOriginalFilePath();
    BOOL FixFunctionAddresses();
    list <va_t> *GetFunctionAddresses();

    void ClearBlockToFunction()
    {
        m_blockToFunction.clear();
        m_functionToBlock.clear();
    }

    bool GetFunctionAddress(va_t address, va_t& function_address)
    {
        multimap <va_t, va_t>::iterator it = m_blockToFunction.find(address);

        if (it != m_blockToFunction.end())
        {
            function_address = it->second;
            return true;
        }
        function_address = 0;
        return false;
    }

    bool FindBlockFunctionMatch(va_t block, va_t function)
    {
        for (multimap <va_t, va_t>::iterator it = m_blockToFunction.find(block); it != m_blockToFunction.end() && it->first == block; it++)
        {
            if (it->second == function)
            {
                return true;
            }
        }
        return false;
    }

    FileInfo *GetClientFileInfo()
    {
        return &m_disassemblyHashMaps->file_info;
    }
};
