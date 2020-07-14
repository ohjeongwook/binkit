#pragma once
#include "StorageDataStructures.h"
#include <vector>
#include "Utility.h"

using namespace std;
using namespace stdext;

void LogMessage(int level, const char* function_name, const char* format, ...);

#ifdef XXX
class InstructionHashMap
{
private:
    multimap <vector<unsigned char>, va_t> m_instructionHashMap;

public:
    InstructionHashMap()
    {
        printf("Calling InstructionHashMap(): %X\n", this);
    }

    ~InstructionHashMap()
    {
        printf("Calling ~InstructionHashMap(): %X\n", this);
    }

    multimap <vector<unsigned char>, va_t>::iterator begin()
    {
        return m_instructionHashMap.begin();
    }

    multimap <vector<unsigned char>, va_t>::iterator end()
    {
        return m_instructionHashMap.end();
    }

    multimap <vector<unsigned char>, va_t>::iterator find(vector<unsigned char> instructionHash)
    {
        return m_instructionHashMap.find(instructionHash);
    }

    multimap <vector<unsigned char>, va_t>::iterator insert(pair<vector<unsigned char>, va_t> values)
    {
        return m_instructionHashMap.insert(values);
    }

    multimap <vector<unsigned char>, va_t>::iterator erase(multimap <vector<unsigned char>, va_t>::iterator it)
    {
        return m_instructionHashMap.erase(it);
    }

    void clear()
    {
        return m_instructionHashMap.clear();
    }

    size_t count(vector<unsigned char> const instructionHash)
    {
        return m_instructionHashMap.count(instructionHash);
    }

    size_t size()
    {
        return m_instructionHashMap.size();
    }
};
#endif

typedef multimap <vector<unsigned char>, va_t> InstructionHashMap;

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

enum { 
    NAME_MATCH,
    INSTRUCTION_HASH_MATCH,
    TWO_LEVEL_INSTRUCTION_HASH_MATCH,
    TREE_MATCH,
    INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH,
    FUNCTION_MATCH,
    CONTROLFLOW_MATCH
};

static const char* MatchDataTypeStr[] = {
    "Name",
    "InstructionHash",
    "Two Level InstructionHash",
    "IsoMorphic Match",
    "InstructionHash Inside Function",
    "Function"
};

typedef struct _MatchData_ {
    short Type;
    short SubType;
    short Status;
    short ReferenceOrderDifference;
    va_t Source;
    va_t Target;
    int MatchRate;
    va_t SourceParent;
    va_t TargetParent;
    int MatchSequence;
} MatchData;
