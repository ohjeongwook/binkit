#pragma once
#include <stdio.h>
#include <string>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "SQLiteTool.h"

using namespace std;

#define FILE_INFO_TABLE "FileInfo"
#define MAP_INFO_TABLE "ControlFlow"
#define CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (SrcBlock)"
#define BASIC_BLOCKS_TABLE "BasicBlocks"
#define UPDATE_BASIC_BLOCKS_TABLE_FUNCTION_ADDRESS_STATEMENT "UPDATE " BASIC_BLOCKS_TABLE" SET FunctionAddress='%u',BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"

class SQLiteDisassemblyReader : public DisassemblyReader
{
private:
    int m_debugLevel = 0;
    SQLiteTool m_sqliteTool;

public:
    SQLiteDisassemblyReader();
    SQLiteDisassemblyReader(string dataBasName);
    ~SQLiteDisassemblyReader();

    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);

    static int ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names);
    void ReadFunctionAddressMap(unordered_set <va_t>& functionAddressMap);

    char *ReadInstructionHash(va_t address);
    string ReadSymbol(va_t address);
    va_t ReadBlockStartAddress(va_t address);

    static int ReadBasicBlockHashCallback(void *arg, int argc, char **argv, char **names);
    void ReadBasicBlockHashes(char *conditionStr, DisassemblyHashMaps *DisassemblyHashMaps);

    static int ReadControlFlowCallback(void *arg, int argc, char **argv, char **names);
    void ReadControlFlow(multimap <va_t, PControlFlow>& addressToControlFlowMap, va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<AddressRange> ReadFunctionMemberAddresses(va_t functionAddress);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    string GetOriginalFilePath();

    string ReadDisasmLine(va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(va_t address);

    bool UpdateBasicBlockFunctions(multimap <va_t, va_t> blockToFunction);
};
