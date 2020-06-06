#pragma once
#include <string>
#include "sqlite3.h"

using namespace std;

class SQLiteTool
{
private:
    int m_debugLevel = 0;
    string m_databaseName;
    sqlite3* m_database;

public:
    bool Open(string databaseName);
    void Close();
    const char* GetDatabaseName();
    int ExecuteStatement(sqlite3_callback callback, void* context, const char* format, ...);

    int BeginTransaction();
    int EndTransaction();
};