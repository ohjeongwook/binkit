#pragma once
#include "StorageDataStructures.h"
#include <vector>

using namespace std;
using namespace stdext;

class InstructionHashEqu
{
public:
    enum
    {
        bucket_size = 400000,
        min_buckets = 4000
    };

    size_t operator() (const vector<unsigned char> bytes) const
    {
        size_t key = 0;
        for(unsigned char byte : bytes)
        {
            key += byte;
        }
        return key;
    }

    bool operator() (const vector<unsigned char> bytes01, const vector<unsigned char> bytes02) const
    {
        return (bytes01 == bytes02);
    }
};

void LogMessage(int level, const char* function_name, const char* format, ...);

class InstructionHashMap
{
private:
    multimap <vector<unsigned char>, va_t, InstructionHashEqu> m_instructionHashMap;

public:

    multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator begin()
    {
        return m_instructionHashMap.begin();
    }

    multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator end()
    {
        return m_instructionHashMap.end();
    }

    multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator find(vector<unsigned char> p_instructionHash)
    {
        return m_instructionHashMap.find(p_instructionHash);
    }

    multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator insert(pair<vector<unsigned char>, va_t> values)
    {
        return m_instructionHashMap.insert(values);
    }

    multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator erase(multimap <vector<unsigned char>, va_t, InstructionHashEqu>::iterator it)
    {
        return m_instructionHashMap.erase(it);
    }

    void clear()
    {
        return m_instructionHashMap.clear();
    }

    int count(vector<unsigned char> const instructionHash)
    {
        return m_instructionHashMap.count(instructionHash);
    }

    int size()
    {
        return m_instructionHashMap.size();
    }
};

typedef struct _DisassemblyHashMaps_ {
    FileInfo file_info;
    InstructionHashMap instructionHashMap;
    multimap <va_t, vector<unsigned char>> addressToInstructionHashMap;
    multimap <string, va_t> symbolMap;
    multimap <va_t, string> addressToSymbolMap;
    multimap <va_t, PControlFlow> addressToControlFlowMap;
    multimap <va_t, va_t> dstToSrcAddressMap;

    void DumpDisassemblyHashMaps()
    {
        LogMessage(10, __FUNCTION__, "OriginalFilePath = %s\n", file_info.OriginalFilePath);
        LogMessage(10, __FUNCTION__, "ComputerName = %s\n", file_info.ComputerName);
        LogMessage(10, __FUNCTION__, "UserName = %s\n", file_info.UserName);
        LogMessage(10, __FUNCTION__, "CompanyName = %s\n", file_info.CompanyName);
        LogMessage(10, __FUNCTION__, "FileVersion = %s\n", file_info.FileVersion);
        LogMessage(10, __FUNCTION__, "FileDescription = %s\n", file_info.FileDescription);
        LogMessage(10, __FUNCTION__, "InternalName = %s\n", file_info.InternalName);
        LogMessage(10, __FUNCTION__, "ProductName = %s\n", file_info.ProductName);
        LogMessage(10, __FUNCTION__, "ModifiedTime = %s\n", file_info.ModifiedTime);
        LogMessage(10, __FUNCTION__, "MD5Sum = %s\n", file_info.MD5Sum);
        LogMessage(10, __FUNCTION__, "instructionHashMap = %u\n", instructionHashMap.size());
    }
} DisassemblyHashMaps, * PDisassemblyHashMaps;

enum { NAME_MATCH, INSTRUCTION_HASH_MATCH, TWO_LEVEL_INSTRUCTION_HASH_MATCH, TREE_MATCH, INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH, FUNCTION_MATCH };

typedef struct _MatchData_ {
    short Type;
    short SubType;
    short Status;
    va_t Addresses[2];
    short MatchRate;
    va_t UnpatchedParentAddress;
    va_t PatchedParentAddress;
} MatchData;
