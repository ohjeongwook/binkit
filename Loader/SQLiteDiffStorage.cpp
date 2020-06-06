#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "SQLiteDiffStorage.h"
#include "Log.h"

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
