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

SQLiteDisassemblyReader::SQLiteDisassemblyReader()
{
}

SQLiteDisassemblyReader::SQLiteDisassemblyReader(string dataBasName)
{
    if (!dataBasName.empty())
    {
        m_sqliteTool.Open(dataBasName);
    }
}

SQLiteDisassemblyReader::~SQLiteDisassemblyReader()
{
    m_sqliteTool.Close();
}

vector<unsigned char> HexToBytes(char *hexBytesString);

int SQLiteDisassemblyReader::ReadBasicBlockHashCallback(void *arg, int argc, char **argv, char **names)
{
    DisassemblyHashMaps *m_disassemblyHashMaps = (DisassemblyHashMaps*)arg;
    if (argv[1] && argv[1][0] != NULL)
    {
        va_t address = strtoul10(argv[0]);
        vector<unsigned char> bytes(HexToBytes(argv[1]));
        m_disassemblyHashMaps->instructionHashMap.insert(pair <vector<unsigned char>, va_t>(bytes, address));
        m_disassemblyHashMaps->addressToInstructionHashMap.insert(pair <va_t, vector<unsigned char>>(address, bytes));

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
    m_sqliteTool.ExecuteStatement(ReadBasicBlockHashCallback,
        (void*)DisassemblyHashMaps,
        "SELECT StartAddress, InstructionHash, Name, BlockType FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u %s",
        m_fileId,
        conditionStr);
}

int SQLiteDisassemblyReader::ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names)
{
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
        FunctionAddressHash->insert(strtoul10(argv[0]));
    }
    return 0;
}

void SQLiteDisassemblyReader::ReadFunctionAddressMap(unordered_set <va_t>& functionAddressMap)
{
    m_sqliteTool.ExecuteStatement(ReadFunctionAddressesCallback, &functionAddressMap, "SELECT DISTINCT(FunctionAddress) FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u AND BlockType = %u", m_fileId, FUNCTION_BLOCK);
}

char *SQLiteDisassemblyReader::ReadInstructionHash(va_t address)
{
    char *instructionHash = NULL;

    m_sqliteTool.ExecuteStatement(ReadRecordStringCallback, &instructionHash, "SELECT InstructionHash FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u and StartAddress = %u", m_fileId, address);
    return instructionHash;
}

string SQLiteDisassemblyReader::ReadSymbol(va_t address)
{
    string name;
    m_sqliteTool.ExecuteStatement(ReadRecordStringCallback, &name,
        "SELECT Name FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u and StartAddress = %u", m_fileId, address);
    return name;
}

va_t SQLiteDisassemblyReader::ReadBlockStartAddress(va_t address)
{
    va_t blockAddress;
    m_sqliteTool.ExecuteStatement(ReadRecordIntegerCallback, &blockAddress,
        "SELECT StartAddress FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u and StartAddress <=  %u  and %u <=  EndAddress LIMIT 1",
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
    p_controlFlow->insert(AddressPControlFlowPair(p_control_flow->SrcBlock, p_control_flow));
    return 0;
}

void SQLiteDisassemblyReader::ReadControlFlow(multimap <va_t, PControlFlow> &addressToControlFlowMap, va_t address, bool isFunction)
{
    if (address == 0)
    {
        m_sqliteTool.ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
            "SELECT Type, SrcBlock, SrcBlockEnd, Dst From " CONTROL_FLOWS_TABLE " WHERE FileID = %u",
            m_fileId);
    }
    else
    {
        if (isFunction)
        {
            ReadControlFlow(addressToControlFlowMap, address, isFunction);

            m_sqliteTool.ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From " CONTROL_FLOWS_TABLE " "
                "WHERE FileID = %u "
                "AND ( SrcBlock IN ( SELECT StartAddress FROM " BASIC_BLOCKS_TABLE " WHERE FunctionAddress='%d') )",
                m_fileId, address);
        }
        else
        {
            m_sqliteTool.ExecuteStatement(ReadControlFlowCallback, (void*)&addressToControlFlowMap,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From " CONTROL_FLOWS_TABLE " "
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

    m_sqliteTool.ExecuteStatement(ReadFunctionMemberAddressesCallback, (void*)&addressRangeList,
        "SELECT StartAddress, EndAddress FROM " BASIC_BLOCKS_TABLE " WHERE FileID = '%d' AND FunctionAddress='%d'"
        "ORDER BY ID ASC",
        m_fileId, functionAddress);

    return addressRangeList;
}

string SQLiteDisassemblyReader::GetOriginalFilePath()
{
    string originalFilePath;
    m_sqliteTool.ExecuteStatement(ReadRecordStringCallback, &originalFilePath,
        "SELECT OriginalFilePath FROM FileInfo WHERE id = %u", m_fileId);

    return originalFilePath;
}

string SQLiteDisassemblyReader::ReadDisasmLine(va_t startAddress)
{
    string disasmLines;
    m_sqliteTool.ExecuteStatement(ReadRecordStringCallback, &disasmLines, "SELECT DisasmLines FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u and StartAddress = %u",
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
    return 0;
}

PBasicBlock SQLiteDisassemblyReader::ReadBasicBlock(va_t address)
{
    PBasicBlock p_basic_block = new BasicBlock();
    m_sqliteTool.ExecuteStatement(ReadBasicBlockCallback, p_basic_block,
        "SELECT StartAddress, EndAddress, Flag, FunctionAddress, BlockType, Name, InstructionHash FROM " BASIC_BLOCKS_TABLE " WHERE FileID = %u and StartAddress = %u",
        m_fileId,
        address);

    return p_basic_block;
}

bool SQLiteDisassemblyReader::UpdateBasicBlockFunctions(multimap <va_t, va_t> blockToFunction)
{
    bool isFixed = false;
    m_sqliteTool.BeginTransaction();

    for (auto& val : blockToFunction)
    {
        LogMessage(0, __FUNCTION__, "Updating BasicBlockTable Address = %X Function = %X\n", val.second, val.first);
        m_sqliteTool.ExecuteStatement(NULL, NULL, UPDATE_BASIC_BLOCKS_TABLE_FUNCTION_ADDRESS_STATEMENT,
            val.second, val.second == val.first ? FUNCTION_BLOCK : UNKNOWN_BLOCK, m_fileId, val.first);
        isFixed = TRUE;
    }

    m_sqliteTool.EndTransaction();

    return isFixed;
}
