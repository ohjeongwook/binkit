#include "Log.h"
#include "SQLiteTool.h"

bool SQLiteTool::Open(string databaseName)
{
    m_databaseName = databaseName;
    int rc = sqlite3_open(databaseName.c_str(), &m_database);
    if (rc)
    {
        printf("Opening Database [%s] Failed\n", databaseName.c_str());
        sqlite3_close(m_database);
        m_database = NULL;
        return FALSE;
    }
    return TRUE;
}

void SQLiteTool::Close()
{
    if (m_database)
    {
        sqlite3_close(m_database);
        m_database = NULL;
    }
}

const char* SQLiteTool::GetDatabaseName()
{
    return m_databaseName.c_str();
}

int SQLiteTool::ExecuteStatement(sqlite3_callback callback, void* context, const char* format, ...)
{
    if (m_database)
    {
        int rc = 0;
        char* statement_buffer = NULL;
        char* zErrMsg = 0;

        va_list args;
        va_start(args, format);
        statement_buffer = sqlite3_vmprintf(format, args);
        va_end(args);

        if (m_debugLevel > 1)
        {
            LogMessage(1, __FUNCTION__, "Executing [%s]\n", statement_buffer);
        }

        if (statement_buffer)
        {
            rc = sqlite3_exec(m_database, statement_buffer, callback, context, &zErrMsg);

            if (rc != SQLITE_OK)
            {
                if (m_debugLevel > 0)
                {
                    LogMessage(1, __FUNCTION__, "SQL error: [%s] [%s]\n", statement_buffer, zErrMsg);
                }
            }
            sqlite3_free(statement_buffer);
        }

        return rc;
    }
    return SQLITE_ERROR;
}
