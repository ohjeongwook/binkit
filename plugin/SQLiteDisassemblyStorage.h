#pragma once
#include <stdio.h>
#include <string>

#include "StorageDataStructures.h"
#include "DisassemblyStorage.h"
#include "SQLiteTool.h"
#include "SQLiteDisassemblyCommon.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define CREATE_BINARIES_TABLE_STATEMENT "CREATE TABLE " BINARIES_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            OriginalFilePath TEXT,\n\
            MD5 VARCHAR(32),\n\
            SHA256 VARCHAR(64)\n\
);"

#define INSERT_BINARIES_TABLE_STATEMENT "INSERT INTO " BINARIES_TABLE " (FileID,OriginalFilePath,MD5,SHA256) values ('%u',%Q,%Q,%Q);"

#define CREATE_CONTROL_FLOWS_TABLE_STATEMENT "CREATE TABLE " CONTROL_FLOWS_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            Type INTEGER,\n\
            SrcBlock INTEGER,\n\
            SrcBlockEnd INTEGER,\n\
            Dst INTEGER\n\
        );"
#define CREATE_CONTROL_FLOWS_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX " CONTROL_FLOWS_TABLE "Index ON "CONTROL_FLOWS_TABLE" (SrcBlock)"
#define INSERT_CONTROL_FLOWS_TABLE_STATEMENT "INSERT INTO " CONTROL_FLOWS_TABLE " (FileID,Type,SrcBlock,SrcBlockEnd,Dst) values ('%u','%u','%u','%u','%u');"

#define CREATE_BASIC_BLOCKS_TABLE_STATEMENT "CREATE TABLE " BASIC_BLOCKS_TABLE " (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            StartAddress INTEGER,\n\
            EndAddress INTEGER,\n\
            Flag INTEGER,\n\
            FunctionAddress INTEGER,\n\
            BlockType INTEGER,\n\
            Name TEXT,\n\
            DisasmLines TEXT,\n\
            InstructionHash TEXT,\n\
            InstructionBytes TEXT\n\
);"

#define CREATE_BASIC_BLOCKS_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCKS_TABLE"FunctionAddressIndex ON "BASIC_BLOCKS_TABLE" (FunctionAddress)"

#define CREATE_BASIC_BLOCKS_TABLE_START_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCKS_TABLE"StartAddressIndex ON "BASIC_BLOCKS_TABLE" (StartAddress)"

#define CREATE_BASIC_BLOCKS_TABLE_END_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCKS_TABLE"EndAddressIndex ON "BASIC_BLOCKS_TABLE" (EndAddress)"

//#define CREATE_BASIC_BLOCKS_TABLE_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCKS_TABLE"AddressIndex ON "BASIC_BLOCKS_TABLE" (FileID,StartAddress,EndAddress,Name,InstructionHash)"
#define INSERT_BASIC_BLOCKS_TABLE_STATEMENT "INSERT INTO  " BASIC_BLOCKS_TABLE" (FileID,StartAddress,EndAddress,Flag,FunctionAddress,BlockType,Name,DisasmLines,InstructionHash,InstructionBytes) values ('%u','%u','%u','%u','%u','%u',%Q,%Q,%Q,%Q);"
#define UPDATE_BASIC_BLOCKS_TABLE_NAME_STATEMENT "UPDATE " BASIC_BLOCKS_TABLE" SET Name=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCKS_TABLE_BLOCK_TYPE_STATEMENT "UPDATE " BASIC_BLOCKS_TABLE" SET BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_BASIC_BLOCKS_TABLE_DISASM_LINES_STATEMENT "UPDATE " BASIC_BLOCKS_TABLE" SET DisasmLines=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCKS_TABLE_INSTRUCTION_HASH_STATEMENT "UPDATE " BASIC_BLOCKS_TABLE" SET InstructionHash=%Q WHERE StartAddress='%u';"

class SQLiteDisassemblyStorage : public DisassemblyStorage
{
private:
    sqlite3 *m_database;
    string m_databaseName;
    SQLiteTool m_sqliteTool;

public:
    SQLiteDisassemblyStorage(const char *DatabaseName = NULL);
    ~SQLiteDisassemblyStorage();

public:
    bool Open(char* databaseName);
    int BeginTransaction();
    int EndTransaction();
    void AddBasicBlock(BasicBlock& basicBlock, int fileID = 0);
    void AddControlFlow(ControlFlow& controlFlow, int fileID = 0);

    void SetBinaryMetaData(BinaryMetaData *pBinaryMetaData, int fileID = 0);
    void CreateTables();
};
