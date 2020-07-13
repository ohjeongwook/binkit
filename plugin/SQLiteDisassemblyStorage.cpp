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
        m_sqliteTool.Open(DatabaseName);
        CreateTables();
    }
}

SQLiteDisassemblyStorage::~SQLiteDisassemblyStorage()
{
    m_sqliteTool.Close();
}

void SQLiteDisassemblyStorage::CreateTables()
{
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);
}

bool SQLiteDisassemblyStorage::Open(char *databaseName)
{
    return m_sqliteTool.Open(databaseName);
}

void SQLiteDisassemblyStorage::SetFileInfo(FileInfo *pFileInfo)
{
    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_FILE_INFO_TABLE_STATEMENT,
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
    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_BASIC_BLOCK_TABLE_STATEMENT,
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
    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_MAP_INFO_TABLE_STATEMENT,
        fileID,
        controlFlow.Type,
        controlFlow.SrcBlock,
        controlFlow.SrcBlockEnd,
        controlFlow.Dst
    );
}
