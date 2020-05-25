#pragma once
#include <stdio.h>
#include <string>

#include "Structures.h"
#include "DisassemblyReader.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define FILE_INFO_TABLE "FileInfo"
#define MAP_INFO_TABLE "ControlFlow"
#define CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (SrcBlock)"
#define BASIC_BLOCK_TABLE "BasicBlock"

class SQLiteDisassemblyReader : public DisassemblyReader
{
private:
    sqlite3 *m_database;
    string m_databaseName;

public:
    SQLiteDisassemblyReader();
    SQLiteDisassemblyReader(string dataBasName);
    ~SQLiteDisassemblyReader();

public:
    void Close();
    bool Open(string dataBasName);
    const char *GetDatabaseName();
    void CloseDatabase();

    void SetFileID(int fileId);
    int ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...);
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
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
    multimap <va_t, PControlFlow> *ReadControlFlow(va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<AddressRange> ReadFunctionMemberAddresses(va_t functionAddress);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    string GetOriginalFilePath();

    string ReadDisasmLine(va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(va_t address);
};
