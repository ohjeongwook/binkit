#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>
#include <map>
#include <iostream>

#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "StorageDataStructures.h"
#include "SQLiteDisassemblyStorage.h"

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
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCKS_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCKS_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCKS_TABLE_START_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCKS_TABLE_END_ADDRESS_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_CONTROL_FLOWS_TABLE_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_CONTROL_FLOWS_TABLE_SRCBLOCK_INDEX_STATEMENT);
    m_sqliteTool.ExecuteStatement(NULL, NULL, CREATE_BINARIES_TABLE_STATEMENT);
}

bool SQLiteDisassemblyStorage::Open(char *databaseName)
{
    return m_sqliteTool.Open(databaseName);
}

int SQLiteDisassemblyStorage::BeginTransaction()
{
    return m_sqliteTool.BeginTransaction();
}

int SQLiteDisassemblyStorage::EndTransaction()
{
    return m_sqliteTool.EndTransaction();
}

void SQLiteDisassemblyStorage::SetBinaryMetaData(BinaryMetaData *pBinaryMetaData, int fileID)
{
    BOOST_LOG_TRIVIAL(debug) << boost::format("OriginalFilePath: %s") % pBinaryMetaData->OriginalFilePath;
    BOOST_LOG_TRIVIAL(debug) << boost::format("MD5: %s") % pBinaryMetaData->MD5.c_str();
    BOOST_LOG_TRIVIAL(debug) << boost::format("SHA256: %s") % pBinaryMetaData->SHA256.c_str();

    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_BINARIES_TABLE_STATEMENT,
        fileID,
        pBinaryMetaData->OriginalFilePath,
        pBinaryMetaData->MD5.c_str(),
        pBinaryMetaData->SHA256.c_str(),
        pBinaryMetaData->ImageBase
    );
}

void SQLiteDisassemblyStorage::AddBasicBlock(BasicBlock &basicBlock, int fileID)
{
    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_BASIC_BLOCKS_TABLE_STATEMENT,
        fileID,
        basicBlock.StartAddress - m_imageBase,
        basicBlock.EndAddress - m_imageBase,
        basicBlock.Flag,
        basicBlock.FunctionAddress - m_imageBase,
        basicBlock.BlockType,
        basicBlock.Name.c_str(),
        basicBlock.DisasmLines.c_str(),
        basicBlock.InstructionHash.c_str(),
        basicBlock.InstructionBytes.c_str()
    );
}

void SQLiteDisassemblyStorage::AddControlFlow(ControlFlow &controlFlow, int fileID)
{
    m_sqliteTool.ExecuteStatement(NULL, NULL, INSERT_CONTROL_FLOWS_TABLE_STATEMENT,
        fileID,
        controlFlow.Type,
        controlFlow.Src - m_imageBase,
        controlFlow.Dst - m_imageBase
    );
}
