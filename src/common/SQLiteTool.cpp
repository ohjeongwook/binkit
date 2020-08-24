#include "SQLiteTool.h"
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

bool SQLiteTool::Open(string databaseName)
{
    m_databaseName = databaseName;
    int rc = sqlite3_open(databaseName.c_str(), &m_database);
    if (rc)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("Opening Database [%s] Failed") % databaseName.c_str();
        sqlite3_close(m_database);
        m_database = NULL;
        return false;
    }

    ExecuteStatement(NULL, NULL, "PRAGMA synchronous = OFF");
    ExecuteStatement(NULL, NULL, "PRAGMA journal_mode = MEMORY");

    return true;
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

        BOOST_LOG_TRIVIAL(debug) << boost::format("Executing [%s]") % statement_buffer;

        if (statement_buffer)
        {
            rc = sqlite3_exec(m_database, statement_buffer, callback, context, &zErrMsg);

            if (rc != SQLITE_OK)
            {
                BOOST_LOG_TRIVIAL(error) << boost::format("SQL error: [%s] [%s]") % statement_buffer % zErrMsg;
            }
            sqlite3_free(statement_buffer);
        }

        return rc;
    }
    return SQLITE_ERROR;
}

int SQLiteTool::BeginTransaction()
{
    return ExecuteStatement(NULL, NULL, "BEGIN TRANSACTION;");
}

int SQLiteTool::EndTransaction()
{
    return ExecuteStatement(NULL, NULL, "END TRANSACTION;");
}

int SQLiteTool::GetLastInsertRowID()
{
    return (int)sqlite3_last_insert_rowid(m_database);
}
