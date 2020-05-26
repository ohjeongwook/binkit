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
#include "SQLiteDisassemblyReader.h"
#include "Log.h"

SQLiteDisassemblyReader::SQLiteDisassemblyReader() : m_database(NULL)
{
}

SQLiteDisassemblyReader::SQLiteDisassemblyReader(string dataBasName): m_database(NULL)
{
    if (!dataBasName.empty())
    {
        Open(dataBasName);
    }
}

SQLiteDisassemblyReader::~SQLiteDisassemblyReader()
{
    CloseDatabase();
}

bool SQLiteDisassemblyReader::Open(string dataBasName)
{
    m_databaseName = dataBasName;
    int rc = sqlite3_open(dataBasName.c_str(), &m_database);
    if (rc)
    {
        printf("Opening Database [%s] Failed\n", dataBasName.c_str());
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

int SQLiteDisassemblyReader::ReadBasicBlockHashCallback(void *arg, int argc, char **argv, char **names)
{
    DisassemblyHashMaps *m_disassemblyHashMaps = (DisassemblyHashMaps*)arg;
    if (argv[1] && argv[1][0] != NULL)
    {
        va_t address = strtoul10(argv[0]);
        unsigned char *instructionHashStr = HexToBytesWithLengthAmble(argv[1]);

        if (instructionHashStr)
        {
            m_disassemblyHashMaps->addressToInstructionHashMap.insert(pair <va_t, unsigned char*>(address, instructionHashStr));
        }

        if (strtoul10(argv[3]) == 1 && strlen(argv[2]) > 0)
        {
            char *name = argv[2];
            m_disassemblyHashMaps->symbolMap.insert(pair<string, va_t>(name, address));
            m_disassemblyHashMaps->addressToSymbolMap.insert(pair<va_t, string>(address, name));
        }
    }
    return 0;
}

void SQLiteDisassemblyReader::ReadBasicBlockHashes(char *conditionStr, DisassemblyHashMaps *DisassemblyHashMaps)
{
    ExecuteStatement(ReadBasicBlockHashCallback,
        (void*)DisassemblyHashMaps,
        "SELECT StartAddress, InstructionHash, Name, BlockType FROM BasicBlock WHERE FileID = %u %s",
        m_fileId,
        conditionStr);
}

void SQLiteDisassemblyReader::Close()
{
    CloseDatabase();
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
    *(string *)arg = string(argv[0]);
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

void SQLiteDisassemblyReader::ReadFunctionAddressMap(unordered_set <va_t>& functionAddressMap)
{
    ExecuteStatement(ReadFunctionAddressesCallback, &functionAddressMap, "SELECT DISTINCT(FunctionAddress) FROM BasicBlock WHERE FileID = %u AND BlockType = %u", m_fileId, FUNCTION_BLOCK);
}

char *SQLiteDisassemblyReader::ReadInstructionHash(va_t address)
{
    char *fingerPrintString = NULL;

    ExecuteStatement(ReadRecordStringCallback, &fingerPrintString, "SELECT InstructionHash FROM BasicBlock WHERE FileID = %u and StartAddress = %u", m_fileId, address);
    return fingerPrintString;
}

string SQLiteDisassemblyReader::ReadSymbol(va_t address)
{
    string name;
    ExecuteStatement(ReadRecordStringCallback, &name,
        "SELECT Name FROM BasicBlock WHERE FileID = %u and StartAddress = %u", m_fileId, address);
    return name;
}

va_t SQLiteDisassemblyReader::ReadBlockStartAddress(va_t address)
{
    va_t blockAddress;
    ExecuteStatement(ReadRecordIntegerCallback, &blockAddress,
        "SELECT StartAddress FROM BasicBlock WHERE FileID = %u and StartAddress <=  %u  and %u <=  EndAddress LIMIT 1",
        m_fileId, address, address);
    return blockAddress;
}

int SQLiteDisassemblyReader::ReadControlFlowCallback(void *arg, int argc, char **argv, char **names)
{
    multimap <va_t, PControlFlow> *p_controlFlow = (multimap <va_t, PControlFlow>*)arg;

    PControlFlow p_control_flow = new ControlFlow;
    p_control_flow->Type = strtoul10(argv[0]);
    p_control_flow->SrcBlock = strtoul10(argv[1]);
    p_control_flow->SrcBlockEnd = strtoul10(argv[2]);
    p_control_flow->Dst = strtoul10(argv[3]);
#if DEBUG_LEVEL > 1
    Logger.Log(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID,
        argv[0], strtoul10(argv[0]),
        argv[1], strtoul10(argv[1]),
        argv[2], strtoul10(argv[2]),
        argv[3], strtoul10(argv[3])
    );
#endif
    p_controlFlow->insert(AddressPControlFlowPair(p_control_flow->SrcBlock, p_control_flow));
    return 0;
}

void SQLiteDisassemblyReader::ReadControlFlow(multimap <va_t, PControlFlow> &addressToControlFlowMap, va_t address, bool isFunction)
{
    if (address == 0)
    {
        ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
            "SELECT Type, SrcBlock, SrcBlockEnd, Dst From ControlFlow WHERE FileID = %u",
            m_fileId);
    }
    else
    {
        if (isFunction)
        {
            ReadControlFlow(addressToControlFlowMap, address, isFunction);

            ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From ControlFlow "
                "WHERE FileID = %u "
                "AND ( SrcBlock IN ( SELECT StartAddress FROM BasicBlock WHERE FunctionAddress='%d') )",
                m_fileId, address);
        }
        else
        {
            ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From ControlFlow "
                "WHERE FileID = %u "
                "AND SrcBlock  = '%d'",
                m_fileId, address);
        }
    }
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

list<AddressRange> SQLiteDisassemblyReader::ReadFunctionMemberAddresses(va_t functionAddress)
{
    list<AddressRange> addressRangeList;

    ExecuteStatement(ReadFunctionMemberAddressesCallback, (void*)&addressRangeList,
        "SELECT StartAddress, EndAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d'"
        "ORDER BY ID ASC",
        m_fileId, functionAddress);

    return addressRangeList;
}

string SQLiteDisassemblyReader::GetOriginalFilePath()
{
    string originalFilePath;
    ExecuteStatement(ReadRecordStringCallback, &originalFilePath,
        "SELECT OriginalFilePath FROM FileInfo WHERE id = %u", m_fileId);

    return originalFilePath;
}

string SQLiteDisassemblyReader::ReadDisasmLine(va_t startAddress)
{
    string disasmLines;
    ExecuteStatement(ReadRecordStringCallback, &disasmLines, "SELECT DisasmLines FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        m_fileId, startAddress);
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
    p_basic_block->Name = argv[5];
    p_basic_block->InstructionHash = argv[6];

#if DEBUG_LEVEL > 1
    LogMessage(0, __FUNCTION__, "%X Block Type: %d\n", p_basic_block->StartAddress, p_basic_block->BlockType);

    if (p_basic_block->BlockType == FUNCTION_BLOCK)
    {
        LogMessage(0, __FUNCTION__, "Function Block: %X\n", p_basic_block->StartAddress);
    }
#endif
    return 0;
}

PBasicBlock SQLiteDisassemblyReader::ReadBasicBlock(va_t address)
{
    PBasicBlock p_basic_block = new BasicBlock();
    ExecuteStatement(ReadBasicBlockCallback, p_basic_block,
        "SELECT StartAddress, EndAddress, Flag, FunctionAddress, BlockType, Name, InstructionHash FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        m_fileId,
        address);

    return p_basic_block;
}
