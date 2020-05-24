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
    SQLiteDisassemblyReader(const char *DatabaseName = NULL);
    ~SQLiteDisassemblyReader();

public:
    void Close();
    bool Open(char *DatabaseName);
    const char *GetDatabaseName();
    void CloseDatabase();
    bool ConnectDatabase(const char *DatabaseName);

    int ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...);
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);

    static int ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names);
    void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap);

    char *ReadInstructionHash(int fileID, va_t address);
    char *ReadSymbol(int fileID, va_t address);
    va_t ReadBlockStartAddress(int fileID, va_t address);

    static int ReadBasicBlockHashCallback(void *arg, int argc, char **argv, char **names);
    void ReadBasicBlockHashes(int fileID, char *conditionStr, DisassemblyHashMaps *DisassemblyHashMaps);

    static int ReadControlFlowCallback(void *arg, int argc, char **argv, char **names);
    multimap <va_t, PControlFlow> *ReadControlFlow(int fileID, va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<AddressRange> ReadFunctionMemberAddresses(int fileID, va_t functionAddress);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    string GetOriginalFilePath(int fileID);

    char *ReadDisasmLine(int fileID, va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(int fileID, va_t address);
};
