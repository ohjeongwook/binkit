#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>
#include <map>
#include <iostream>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "StorageDataStructures.h"
#include "SQLiteDisassemblyStorage.h"
#include "Log.h"

SQLiteDisassemblyStorage::SQLiteDisassemblyStorage(const char *DatabaseName)
{
    m_database = NULL;
    if (DatabaseName)
    {
        ConnectDatabase(DatabaseName);
        CreateTables();
    }
}

SQLiteDisassemblyStorage::~SQLiteDisassemblyStorage()
{
    CloseDatabase();
}

void SQLiteDisassemblyStorage::CreateTables()
{
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);
}

bool SQLiteDisassemblyStorage::Open(char *DatabaseName)
{
    m_databaseName = DatabaseName;
    return ConnectDatabase(DatabaseName);
}

bool SQLiteDisassemblyStorage::ConnectDatabase(const char *DatabaseName)
{
    //Database Setup
    m_databaseName = DatabaseName;
    int rc = sqlite3_open(DatabaseName, &m_database);
    if (rc)
    {
        printf("Opening Database [%s] Failed\n", DatabaseName);
        sqlite3_close(m_database);
        m_database = NULL;
        return FALSE;
    }
    return TRUE;
}

const char *SQLiteDisassemblyStorage::GetDatabaseName()
{
    return m_databaseName.c_str();
}

void SQLiteDisassemblyStorage::CloseDatabase()
{
    //Close Database
    if (m_database)
    {
        sqlite3_close(m_database);
        m_database = NULL;
    }
}

int SQLiteDisassemblyStorage::BeginTransaction()
{
    return ExecuteStatement(NULL, NULL, "BEGIN TRANSACTION");
}

int SQLiteDisassemblyStorage::EndTransaction()
{
    return ExecuteStatement(NULL, NULL, "COMMIT TRANSACTION");
}

int SQLiteDisassemblyStorage::GetLastInsertRowID()
{
    return (int)sqlite3_last_insert_rowid(m_database);
}

int SQLiteDisassemblyStorage::ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...)
{
    int debug = 0;

    if (m_database)
    {
        int rc = 0;
        char *statement_buffer = NULL;
        char *zErrMsg = 0;

        va_list args;
        va_start(args, format);
#ifdef USE_VSNPRINTF
        int statement_buffer_len = 0;

        while (1)
        {
            statement_buffer_len += 1024;
            statement_buffer = (char*)malloc(statement_buffer_len);
            memset(statement_buffer, 0, statement_buffer_len);
            if (statement_buffer && _vsnprintf(statement_buffer, statement_buffer_len, format, args) != -1)
            {
                free(statement_buffer);
                break;
            }

            if (!statement_buffer)
                break;
            free(statement_buffer);
        }
#else
        statement_buffer = sqlite3_vmprintf(format, args);
#endif
        va_end(args);

        if (debug > 1)
        {
            LogMessage(1, __FUNCTION__, TEXT("Executing [%s]\n"), statement_buffer);
        }

        if (statement_buffer)
        {
            rc = sqlite3_exec(m_database, statement_buffer, callback, context, &zErrMsg);

            if (rc != SQLITE_OK)
            {
                if (debug > 0)
                {
#ifdef IDA_PLUGIN				
                    LogMessage(1, __FUNCTION__, "SQL error: [%s] [%s]\n", statement_buffer, zErrMsg);
#else
                    LogMessage(1, __FUNCTION__, "SQL error: [%s] [%s]\n", statement_buffer, zErrMsg);
#endif
                }
            }
#ifdef USE_VSNPRINTF
            free(statement_buffer);
#else
            sqlite3_free(statement_buffer);
#endif
        }

        return rc;
    }
    return SQLITE_ERROR;
}

void SQLiteDisassemblyStorage::SetFileInfo(FileInfo *pFileInfo)
{
    ExecuteStatement(NULL, NULL, INSERT_FILE_INFO_TABLE_STATEMENT,
        pFileInfo->OriginalFilePath,
        pFileInfo->ComputerName,
        pFileInfo->UserName,
        pFileInfo->CompanyName,
        pFileInfo->FileVersion,
        pFileInfo->FileDescription,
        pFileInfo->InternalName,
        pFileInfo->ProductName,
        pFileInfo->ModifiedTime,
        pFileInfo->MD5Sum
    );
}

void SQLiteDisassemblyStorage::AddBasicBlock(BasicBlock &basicBlock, int fileID)
{
    ExecuteStatement(NULL, NULL, INSERT_BASIC_BLOCK_TABLE_STATEMENT,
        fileID,
        basicBlock.StartAddress,
        basicBlock.EndAddress,
        basicBlock.Flag,
        basicBlock.FunctionAddress,
        basicBlock.BlockType,
        basicBlock.Name.c_str(),
        basicBlock.DisasmLines.c_str(),
        basicBlock.InstructionHash.c_str()
    );
}

void SQLiteDisassemblyStorage::AddControlFlow(ControlFlow &controlFlow, int fileID)
{
    ExecuteStatement(NULL, NULL, INSERT_MAP_INFO_TABLE_STATEMENT,
        fileID,
        controlFlow.Type,
        controlFlow.SrcBlock,
        controlFlow.SrcBlockEnd,
        controlFlow.Dst
    );
}

void SQLiteDisassemblyStorage::Close()
{
    CloseDatabase();
}
