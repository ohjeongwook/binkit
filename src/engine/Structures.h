#pragma once
#include "StorageDataStructures.h"
#include <vector>
#include "Utility.h"

#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;
using namespace stdext;

class InstructionHashMap
{
private:
    multimap <vector<unsigned char>, va_t> m_instructionHashMap;
    multimap <va_t, vector<unsigned char>> m_addressToInstructionHashMap;

public:
    void Add(vector<unsigned char> bytes, va_t address)
    {
        m_instructionHashMap.insert(pair <vector<unsigned char>, va_t>(bytes, address));
        m_addressToInstructionHashMap.insert(pair <va_t, vector<unsigned char>>(address, bytes));
    }

    vector<vector<unsigned char>> GetUniqueHashes()
    {
        vector<vector<unsigned char>> hashes;

        for (auto& val : m_instructionHashMap)
        {
            if (m_instructionHashMap.count(val.first))
            {
                hashes.push_back(val.first);
            }
        }
        return hashes;
    }
    
    vector<unsigned char> GetInstructionHash(va_t address)
    {
        multimap <va_t, vector<unsigned char>>::iterator it = m_addressToInstructionHashMap.find(address);
        if (it != m_addressToInstructionHashMap.end())
        {
            return it->second;
        }
        return {};
    }

    vector<va_t> GetHashMatches(vector<unsigned char> hash)
    {
        vector<va_t> addresses;
        for (multimap <vector<unsigned char>, va_t>::iterator it = m_instructionHashMap.find(hash); it != m_instructionHashMap.end(); it++)
        {
            if (it->first != hash)
                break;
            addresses.push_back(it->second);
        }

        return addresses;
    }    

    int Count(vector<unsigned char> hash)
    {
        return m_instructionHashMap.count(hash);
    }

    int Size()
    {
        return m_instructionHashMap.size();
    }

    void Clear()
    {
        m_instructionHashMap.clear();
    }
};

typedef struct _DisassemblyHashMaps_ {
    InstructionHashMap instructionHashMap;
    multimap <string, va_t> symbolMap;
    multimap <va_t, string> addressToSymbolMap;
    multimap <va_t, va_t> addressRangeMap;

    void DumpDisassemblyHashMaps()
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("instructionHashMap = %u") % instructionHashMap.Size();
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

static const char* BasicBlockMatchTypeStr[] = {
    "Name",
    "InstructionHash",
    "Two Level InstructionHash",
    "IsoMorphic Match",
    "InstructionHash Inside Function",
    "Function"
};

#define CREF_FROM_MATCH 1
#define CREF_TO_MATCH 2
#define DREF_FROM_MATCH 4
#define DREF_TO_MATCH 8
#define CALL_MATCH 0x10
#define CALLED_MATCH 0x20

typedef struct _BasicBlockMatch_ {
    short Type;
    short SubType;
    short Status;
    va_t Source;
    va_t Target;
    int MatchRate;
    va_t SourceParent;
    va_t TargetParent;
    int MatchSequence;
    int Flags;
} BasicBlockMatch;
