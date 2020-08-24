#pragma once
#include "StorageDataStructures.h"
#include <vector>
#include "Utility.h"

#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;
using namespace stdext;


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
    BinaryMetaData binaryMetaData;
    InstructionHashMap instructionHashMap;
    multimap <va_t, vector<unsigned char>> addressToInstructionHashMap;
    multimap <string, va_t> symbolMap;
    multimap <va_t, string> addressToSymbolMap;
    multimap <va_t, PControlFlow> addressToControlFlowMap;
    multimap <va_t, va_t> dstToSrcAddressMap;

    void DumpDisassemblyHashMaps()
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("OriginalFilePath = %s") % binaryMetaData.OriginalFilePath;
        BOOST_LOG_TRIVIAL(debug) << boost::format("instructionHashMap = %u") % instructionHashMap.size();
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

typedef struct _BasicBlockMatch_ {
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
} BasicBlockMatch;
