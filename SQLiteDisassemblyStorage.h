#pragma once
#include <stdio.h>
#include <string>

#include "StorageDataStructures.h"
#include "DisassemblyStorage.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define FILE_INFO_TABLE "FileInfo"
#define CREATE_FILE_INFO_TABLE_STATEMENT "CREATE TABLE " FILE_INFO_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            OriginalFilePath TEXT,\n\
            ComputerName VARCHAR(100),\n\
            UserName VARCHAR(100),\n\
            CompanyName VARCHAR(100),\n\
            FileVersion VARCHAR(100),\n\
            FileDescription VARCHAR(100),\n\
            InternalName VARCHAR(100),\n\
            ProductName VARCHAR(100),\n\
            ModifiedTime VARCHAR(100),\n\
            MD5Sum VARCHAR(100)\n\
);"
#define INSERT_FILE_INFO_TABLE_STATEMENT "INSERT INTO  " FILE_INFO_TABLE" (OriginalFilePath,ComputerName,UserName,CompanyName,FileVersion,FileDescription,InternalName,ProductName,ModifiedTime,MD5Sum) values (%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q);"

#define MAP_INFO_TABLE "MapInfo"
#define CREATE_MAP_INFO_TABLE_STATEMENT "CREATE TABLE " MAP_INFO_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            Type INTEGER,\n\
            SrcBlock INTEGER,\n\
            SrcBlockEnd INTEGER,\n\
            Dst INTEGER\n\
        );"
#define CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (SrcBlock)"
#define INSERT_MAP_INFO_TABLE_STATEMENT "INSERT INTO  " MAP_INFO_TABLE" (FileID,Type,SrcBlock,SrcBlockEnd,Dst) values ('%u','%u','%u','%u','%u');"

#define BASIC_BLOCK_TABLE "BasicBlock"
#define CREATE_BASIC_BLOCK_TABLE_STATEMENT "CREATE TABLE " BASIC_BLOCK_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            StartAddress INTEGER,\n\
            EndAddress INTEGER,\n\
            Flag INTEGER,\n\
            FunctionAddress INTEGER,\n\
            BlockType INTEGER,\n\
            Name TEXT,\n\
            DisasmLines TEXT,\n\
            Fingerprint TEXT\n\
);"

#define CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"FunctionAddressIndex ON "BASIC_BLOCK_TABLE" (FunctionAddress)"

#define CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"StartAddressIndex ON "BASIC_BLOCK_TABLE" (StartAddress)"

#define CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"EndAddressIndex ON "BASIC_BLOCK_TABLE" (EndAddress)"

//#define CREATE_BASIC_BLOCK_TABLE_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"AddressIndex ON "BASIC_BLOCK_TABLE" (FileID,StartAddress,EndAddress,Name,Fingerprint)"
#define INSERT_BASIC_BLOCK_TABLE_STATEMENT "INSERT INTO  " BASIC_BLOCK_TABLE" (FileID,StartAddress,EndAddress,Flag,FunctionAddress,BlockType,Name,DisasmLines,Fingerprint) values ('%u','%u','%u','%u','%u','%u',%Q,%Q,%Q);"
#define UPDATE_BASIC_BLOCK_TABLE_NAME_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET Name=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET FunctionAddress='%u',BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_BLOCK_TYPE_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_DISASM_LINES_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET DisasmLines=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_FINGERPRINT_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET Fingerprint=%Q WHERE StartAddress='%u';"

class SQLiteDisassemblyStorage : public DisassemblyStorage
{
private:
    sqlite3 *m_database;
    string m_databaseName;

public:
    SQLiteDisassemblyStorage(const char *DatabaseName = NULL);
    ~SQLiteDisassemblyStorage();

public:
    void SetFileInfo(FileInfo *p_file_info);
    int BeginTransaction();
    int EndTransaction();
    void Close();
    void AddBasicBlock(PBasicBlock pBasicBlock, int fileID = 0);
    void AddMapInfo(PMapInfo p_map_info, int fileID = 0);

    int ProcessTLV(BYTE Type, PBYTE Data, DWORD Length);

    void CreateTables();
    bool Open(char *DatabaseName);
    const char *GetDatabaseName();
    void CloseDatabase();
    bool ConnectDatabase(const char *DatabaseName);

    int GetLastInsertRowID();
    int ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...);
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);

    static int ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names);
    void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap);

    char *ReadFingerPrint(int fileID, va_t address);
    char *ReadName(int fileID, va_t address);
    va_t ReadBlockStartAddress(int fileID, va_t address);

    static int ReadBasicBlockDataCallback(void *arg, int argc, char **argv, char **names);

    static int ReadMapInfoCallback(void *arg, int argc, char **argv, char **names);
    multimap <va_t, PMapInfo> *ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    char *GetOriginalFilePath(int fileID);

    char *ReadDisasmLine(int fileID, va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(int fileID, va_t address);

    void UpdateBasicBlock(int fileID, va_t address1, va_t address2);
};
