#pragma once
#include <stdio.h>
#include <string>

#include "DiffStorage.h"
#include "sqlite3.h"
#include "SQLiteTool.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define MATCH_MAP_TABLE "MatchMap"
#define CREATE_MATCH_MAP_TABLE_STATEMENT "CREATE TABLE " MATCH_MAP_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            TheSourceFileID INTEGER, \n\
            TheTargetFileID INTEGER, \n\
            SourceAddress INTEGER, \n\
            TargetAddress INTEGER, \n\
            MatchType INTEGER, \n\
            Type INTEGER, \n\
            SubType INTEGER, \n\
            Status INTEGER, \n\
            MatchRate INTEGER, \n\
            UnpatchedParentAddress INTEGER, \n\
            PatchedParentAddress INTEGER\n\
         );"

#define INSERT_MATCH_MAP_TABLE_STATEMENT "INSERT INTO  "MATCH_MAP_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, TargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_MATCH_MAP_TABLE_STATEMENT "DELETE FROM "MATCH_MAP_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"SourceAddressIndex ON "MATCH_MAP_TABLE" ( SourceAddress )"
#define CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"TargetAddressIndex ON "MATCH_MAP_TABLE" ( TargetAddress )"

#define UNIDENTIFIED_BLOCKS_TABLE "UnidentifiedBlocks"
#define CREATE_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "CREATE TABLE "UNIDENTIFIED_BLOCKS_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            OldFileID INTEGER, \n\
            NewFileID INTEGER, \n\
            Type INTEGER, \n\
            Address INTEGER\n\
         );"
#define INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "INSERT INTO  "UNIDENTIFIED_BLOCKS_TABLE" ( Type, Address ) values ( '%u', '%u' );"

#define FUNCTION_MATCH_INFO_TABLE "FunctionMatchInfo"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "CREATE TABLE " FUNCTION_MATCH_INFO_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            TheSourceFileID INTEGER, \n\
            TheTargetFileID INTEGER, \n\
            SourceAddress INTEGER, \n\
            EndAddress INTEGER, \n\
            TargetAddress INTEGER, \n\
            BlockType INTEGER, \n\
            MatchRate INTEGER, \n\
            SourceFunctionName TEXT, \n\
            Type INTEGER, \n\
            TargetFunctionName TEXT, \n\
            MatchCountForTheSource INTEGER, \n\
            NoneMatchCountForTheSource INTEGER, \n\
            MatchCountWithModificationForTheSource INTEGER, \n\
            MatchCountForTheTarget INTEGER, \n\
            NoneMatchCountForTheTarget INTEGER, \n\
            MatchCountWithModificationForTheTarget INTEGER, \n\
            SecurityImplicationsScore INTEGER \n\
         );"
#define INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT "INSERT INTO  " FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, EndAddress, TargetAddress, BlockType, MatchRate, SourceFunctionName, Type, TargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%s', '%u', '%s', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "DELETE FROM "FUNCTION_MATCH_INFO_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "FUNCTION_MATCH_INFO_TABLE"Index ON "FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, TargetAddress )"

#define FILE_LIST_TABLE "FileList"
#define CREATE_FILE_LIST_TABLE_STATEMENT "CREATE TABLE " FILE_LIST_TABLE " ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            Type VARCHAR(25), \n\
            Filename VARCHAR(255), \n\
            FileID INTEGER, \n\
            FunctionAddress INTEGER\n\
         );"
#define INSERT_FILE_LIST_TABLE_STATEMENT "INSERT INTO  "FILE_LIST_TABLE" ( Type, Filename, FileID, FunctionAddress ) values ( '%s', '%s', '%d', '%d' );"

class SQLiteDiffStorage : public DiffStorage
{
private:
    SQLiteTool m_sqliteTool;

public:
    SQLiteDiffStorage(const char * databaseName = NULL);
    ~SQLiteDiffStorage();
    void CreateTables();

public:
};
