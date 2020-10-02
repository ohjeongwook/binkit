#pragma once
#include "StorageDataStructures.h"
#include <vector>
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;
using namespace stdext;

#include "Utility.h"
#include "InstructionHash.h"

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
