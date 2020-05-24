#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>
#include <map>
#include <iostream>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

// #include "Common.h"
#include "StorageDataStructures.h"
#include "SQLiteDisassemblyReader.h"
#include "Log.h"

SQLiteDisassemblyReader::SQLiteDisassemblyReader(const char *DatabaseName)
{
    m_database = NULL;
    if (DatabaseName)
    {
        ConnectDatabase(DatabaseName);
    }
}

SQLiteDisassemblyReader::~SQLiteDisassemblyReader()
{
    CloseDatabase();
}

bool SQLiteDisassemblyReader::Open(char *DatabaseName)
{
    m_databaseName = DatabaseName;
    return ConnectDatabase(DatabaseName);
}

bool SQLiteDisassemblyReader::ConnectDatabase(const char *DatabaseName)
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

const char *SQLiteDisassemblyReader::GetDatabaseName()
{
    return m_databaseName.c_str();
}

void SQLiteDisassemblyReader::CloseDatabase()
{
    //Close Database
    if (m_database)
    {
        sqlite3_close(m_database);
        m_database = NULL;
    }
}

int SQLiteDisassemblyReader::ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...)
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
            LogMessage(1, __FUNCTION__, "Executing [%s]\n", statement_buffer);
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

unsigned char *HexToBytesWithLengthAmble(char *HexBytes);
typedef pair <va_t, unsigned char*> AddressInstructionHashAddress_Pair;

int SQLiteDisassemblyReader::ReadBasicBlockDataCallback(void *arg, int argc, char **argv, char **names)
{
    DisassemblyHashMaps *m_disassemblyHashMaps = (DisassemblyHashMaps*)arg;
    if (argv[1] && argv[1][0] != NULL)
    {
        va_t Address = strtoul10(argv[0]);
        unsigned char *InstructionHashStr = HexToBytesWithLengthAmble(argv[1]);
        if (InstructionHashStr)
        {
            m_disassemblyHashMaps->address_to_instruction_hash_map.insert(AddressInstructionHashAddress_Pair(Address, InstructionHashStr));
        }

        if (strtoul10(argv[3]) == 1 && strlen(argv[2]) > 0)
        {
            char *name = argv[2];
            m_disassemblyHashMaps->symbol_map.insert(pair<string, va_t>(name, Address));
        }
    }
    return 0;
}

void SQLiteDisassemblyReader::ReadBasicBlockInfo(int fileID, char *conditionStr, DisassemblyHashMaps *DisassemblyHashMaps)
{
    ExecuteStatement(ReadBasicBlockDataCallback,
        (void*)DisassemblyHashMaps,
        "SELECT StartAddress, InstructionHash, Name, BlockType FROM BasicBlock WHERE FileID = %u %s",
        fileID,
        conditionStr);
}

void SQLiteDisassemblyReader::Close()
{
    CloseDatabase();
}

int SQLiteDisassemblyReader::display_callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++) {
        LogMessage(1, __FUNCTION__, "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    return 0;
}

int SQLiteDisassemblyReader::ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names)
{
#if DEBUG_LEVEL > 2
    printf("%s: arg=%x %d\n", __FUNCTION__, arg, argc);
    for (int i = 0; i < argc; i++)
    {
        printf("	[%d] %s=%s\n", i, names[i], argv[i]);
    }
#endif
     *(int*)arg = atoi(argv[0]);
    return 0;
}

int SQLiteDisassemblyReader::ReadRecordStringCallback(void *arg, int argc, char **argv, char **names)
{
#if DEBUG_LEVEL > 2
    printf("%s: arg=%x %d\n", __FUNCTION__, arg, argc);
    for (int i = 0; i < argc; i++)
    {
        printf("	[%d] %s=%s\n", i, names[i], argv[i]);
    }
#endif
     *(char**)arg = _strdup(argv[0]);
    return 0;
}

int SQLiteDisassemblyReader::ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names)
{
    unordered_set <va_t> *FunctionAddressHash = (unordered_set <va_t>*)arg;
    if (FunctionAddressHash)
    {
#if DEBUG_LEVEL > 1
        if (DebugLevel & 1) Logger.Log(10, __FUNCTION__, "%s: ID = %d strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID, argv[0], strtoul10(argv[0]));
#endif
        FunctionAddressHash->insert(strtoul10(argv[0]));
    }
    return 0;
}

void SQLiteDisassemblyReader::ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap)
{
    ExecuteStatement(ReadFunctionAddressesCallback, &functionAddressMap, "SELECT DISTINCT(FunctionAddress) FROM BasicBlock WHERE FileID = %u AND BlockType = %u", fileID, FUNCTION_BLOCK);
}

char *SQLiteDisassemblyReader::ReadInstructionHash(int fileID, va_t address)
{
    char *fingerPrintString = NULL;

    ExecuteStatement(ReadRecordStringCallback, &fingerPrintString, "SELECT InstructionHash FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return fingerPrintString;
}

char *SQLiteDisassemblyReader::ReadSymbol(int fileID, va_t address)
{
    char *name = NULL;
    ExecuteStatement(ReadRecordStringCallback, &name,
        "SELECT Name FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return name;
}

va_t SQLiteDisassemblyReader::ReadBlockStartAddress(int fileID, va_t address)
{
    va_t blockAddress;
    ExecuteStatement(ReadRecordIntegerCallback, &blockAddress,
        "SELECT StartAddress FROM BasicBlock WHERE FileID = %u and StartAddress <=  %u  and %u <=  EndAddress LIMIT 1",
        fileID, address, address);
    return blockAddress;
}

int SQLiteDisassemblyReader::ReadMapInfoCallback(void *arg, int argc, char **argv, char **names)
{
    multimap <va_t, PMapInfo> *p_map_info_map = (multimap <va_t, PMapInfo>*)arg;

    PMapInfo p_map_info = new MapInfo;
    p_map_info->Type = strtoul10(argv[0]);
    p_map_info->SrcBlock = strtoul10(argv[1]);
    p_map_info->SrcBlockEnd = strtoul10(argv[2]);
    p_map_info->Dst = strtoul10(argv[3]);
#if DEBUG_LEVEL > 1
    Logger.Log(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID,
        argv[0], strtoul10(argv[0]),
        argv[1], strtoul10(argv[1]),
        argv[2], strtoul10(argv[2]),
        argv[3], strtoul10(argv[3])
    );
#endif
    p_map_info_map->insert(AddressPMapInfoPair(p_map_info->SrcBlock, p_map_info));
    return 0;
}

multimap <va_t, PMapInfo> *SQLiteDisassemblyReader::ReadMapInfo(int fileID, va_t address, bool isFunction)
{
    multimap <va_t, PMapInfo> *p_map_info_map = new multimap <va_t, PMapInfo>();
    if (address == 0)
    {
        ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
            "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo WHERE FileID = %u",
            fileID);
    }
    else
    {
        if (isFunction)
        {
            p_map_info_map = ReadMapInfo(fileID, address, isFunction);

            ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo "
                "WHERE FileID = %u "
                "AND ( SrcBlock IN ( SELECT StartAddress FROM BasicBlock WHERE FunctionAddress='%d') )",
                fileID, address);
        }
        else
        {
            ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo "
                "WHERE FileID = %u "
                "AND SrcBlock  = '%d'",
                fileID, address);
        }
    }

    return p_map_info_map;
}

int SQLiteDisassemblyReader::ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names)
{
    list <AddressRange> *p_address_list = (list <AddressRange>*)arg;
    if (p_address_list)
    {
#if DEBUG_LEVEL > 1
        if (DebugLevel & 1) Logger.Log(10, __FUNCTION__, "%s: ID = %d strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID, argv[0], strtoul10(argv[0]));
#endif
        AddressRange addressRange;
        addressRange.Start = strtoul10(argv[0]);
        addressRange.End = strtoul10(argv[1]);
        p_address_list->push_back(addressRange);
    }
    return 0;
}

list<AddressRange> SQLiteDisassemblyReader::ReadFunctionMemberAddresses(int fileID, va_t function_address)
{
    list<AddressRange> addressRangeList;

    ExecuteStatement(ReadFunctionMemberAddressesCallback, (void*)&addressRangeList,
        "SELECT StartAddress, EndAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d'"
        "ORDER BY ID ASC",
        fileID, function_address);

    return addressRangeList;
}

char *SQLiteDisassemblyReader::GetOriginalFilePath(int fileID)
{
    char *originalFilePath;
    ExecuteStatement(ReadRecordStringCallback, &originalFilePath,
        "SELECT OriginalFilePath FROM FileInfo WHERE id = %u", fileID);

    return originalFilePath;
}

char *SQLiteDisassemblyReader::ReadDisasmLine(int fileID, va_t startAddress)
{
    char *disasmLines = NULL;
    ExecuteStatement(ReadRecordStringCallback, &disasmLines, "SELECT DisasmLines FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID, startAddress);
    return disasmLines;
}

int SQLiteDisassemblyReader::ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names)
{
    PBasicBlock p_basic_block = (PBasicBlock)arg;
    p_basic_block->StartAddress = strtoul10(argv[0]);
    p_basic_block->EndAddress = strtoul10(argv[1]);
    p_basic_block->Flag = strtoul10(argv[2]);
    p_basic_block->FunctionAddress = strtoul10(argv[3]);
    p_basic_block->BlockType = strtoul10(argv[4]);
    p_basic_block->InstructionHashLen = strlen(argv[5]);

    LogMessage(0, __FUNCTION__, "%X Block Type: %d\n", p_basic_block->StartAddress, p_basic_block->BlockType);

    if (p_basic_block->BlockType == FUNCTION_BLOCK)
    {
        LogMessage(0, __FUNCTION__, "Function Block: %X\n", p_basic_block->StartAddress);
    }
    return 0;
}

PBasicBlock SQLiteDisassemblyReader::ReadBasicBlock(int fileID, va_t address)
{
    PBasicBlock p_basic_block = (PBasicBlock)malloc(sizeof(BasicBlock));
    ExecuteStatement(ReadBasicBlockCallback, p_basic_block,
        "SELECT StartAddress, EndAddress, Flag, FunctionAddress, BlockType, InstructionHash FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID,
        address);

    return p_basic_block;
}
