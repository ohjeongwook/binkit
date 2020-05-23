#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Common.h"
#include "DisassemblyReader.h"

using namespace std;
using namespace stdext;

class Loader
{
private:
    int m_FileID;
    DisassemblyReader *m_pdisassemblyReader;

    char *m_OriginalFilePath;
    va_t TargetFunctionAddress;

    AnalysisInfo *ClientAnalysisInfo;
    char *DisasmLine;
    void GenerateTwoLevelInstructionHash();
    void MergeBlocks();
public:
    AnalysisInfo *GetClientAnalysisInfo()
    {
        return ClientAnalysisInfo;
    }

    FileInfo *GetClientFileInfo()
    {
        return &ClientAnalysisInfo->file_info;
    }
    Loader(DisassemblyReader *DisassemblyReader = NULL);
    ~Loader();
    BOOL Retrieve(char *DataFile, DWORD Offset = 0L, DWORD Length = 0L);

    void SetFileID(int FileID = 1);
    void LoadMapInfo(multimap <va_t, PMapInfo> *p_map_info_map, va_t Address, bool IsFunction = false);
    BOOL Load();

    void AddAnalysisTargetFunction(va_t FunctionAddress);
    BOOL LoadBasicBlock();

    BOOL Save(char *DataFile, DWORD Offset = 0L, DWORD dwMoveMethod = FILE_BEGIN, unordered_set <va_t> *pSelectedAddresses = NULL);
    void DumpAnalysisInfo();
    char *GetName(va_t address);
    void DumpBlockInfo(va_t block_address);
    char *GetInstructionHashStr(va_t address);
    void RemoveFromInstructionHashHash(va_t address);
    va_t GetBlockAddress(va_t address);
    va_t *GetMappedAddresses(va_t address, int type, int *p_length);
    char *GetDisasmLines(unsigned long start_addr, unsigned long end_addr);

    string Identity;

    multimap <va_t, va_t> CrefToMap;
    void BuildCrefToMap(multimap <va_t, PMapInfo> *p_map_info_map);

    multimap <va_t, va_t> BlockToFunction;
    multimap <va_t, va_t> FunctionToBlock;
    unordered_set <va_t> FunctionHeads;
public:
    bool GetFunctionAddress(va_t address, va_t& function_address)
    {
        multimap <va_t, va_t>::iterator it = BlockToFunction.find(address);

        if (it != BlockToFunction.end())
        {
            function_address = it->second;
            return true;
        }
        function_address = 0;
        return false;
    }

    bool FindBlockFunctionMatch(va_t block, va_t function)
    {
        for (multimap <va_t, va_t>::iterator it = BlockToFunction.find(block); it != BlockToFunction.end() && it->first == block; it++)
        {
            if (it->second == function)
            {
                return true;
            }
        }
        return false;
    }

    void LoadBlockToFunction();
    multimap <va_t, va_t> *GetFunctionToBlock();
    void ClearBlockToFunction()
    {
        BlockToFunction.clear();
        FunctionToBlock.clear();
    }

    string GetIdentity();

    PBasicBlock GetBasicBlock(va_t address);
    void FreeDisasmLines();
    list <BLOCK> GetFunctionMemberBlocks(unsigned long FunctionAddress);
    int GetFileID();
    char *GetOriginalFilePath();

    BOOL FixFunctionAddresses();
    list <va_t> *GetFunctionAddresses();
};

unsigned char HexToChar(char *Hex);
unsigned char *HexToBytes(char *HexBytes, int *pLen);
unsigned char *HexToBytesWithLengthAmble(char *HexBytes);
char *BytesWithLengthAmbleToHex(unsigned char *Bytes);
int IsEqualByteWithLengthAmble(unsigned char *Bytes01, unsigned char *Bytes02);
