#pragma once
#include <stdio.h>
#include <string>

using namespace std;

#include "sqlite3.h"

#include "SQLiteDiffStorage.h"

SQLiteDiffStorage::SQLiteDiffStorage(const char* databaseName)
{
    m_sqliteTool.Open(databaseName);
    CreateTables();
}

SQLiteDiffStorage::~SQLiteDiffStorage()
{
    m_sqliteTool.Close();
}

void SQLiteDiffStorage::CreateTables()
{
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_FILE_LIST_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT);
}
