#include "Utility.h"
#include "BasicBlocks.h"
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

const char* ControlFlowTypesStr[] = { "Call", "Cref From", "Cref To", "Dref From", "Dref To" };

BasicBlocks::BasicBlocks(DisassemblyReader* p_disassemblyReader, bool load)
{
    m_pdisassemblyReader = p_disassemblyReader;

    if (load)
    {
        LoadData();
    }
}

BasicBlocks::~BasicBlocks()
{
    m_disassemblyHashMaps.symbolMap.clear();

    for (auto& val : m_addressToControlFlowMap)
    {
        if (val.second)
            delete val.second;
    }
    m_addressToControlFlowMap.clear();
    m_disassemblyHashMaps.instructionHashMap.Clear();
}

void BasicBlocks::LoadData(va_t functionAddress)
{
    char conditionStr[50] = { 0, };
    if (functionAddress)
    {
        int ret = _snprintf_s(conditionStr, _countof(conditionStr), _TRUNCATE, "AND FunctionAddress = '%d'", functionAddress);
    }
    m_pdisassemblyReader->ReadBasicBlockHashes(conditionStr, &m_disassemblyHashMaps);

    m_pdisassemblyReader->ReadControlFlow(m_addressToControlFlowMap, functionAddress, true);
    for (auto& val : m_addressToControlFlowMap)
    {
        if (val.second->Type == CREF_FROM)
        {
            m_dstToSrcAddressMap.insert(pair<va_t, va_t>(val.second->Dst, val.first));
        }
    }
}

void BasicBlocks::MergeBlocks()
{
    multimap <va_t, PControlFlow>::iterator lastIt = m_addressToControlFlowMap.end();
    multimap <va_t, PControlFlow>::iterator it;
    multimap <va_t, PControlFlow>::iterator childIt;

    int NumberOfChildren = 1;
    for (it = m_addressToControlFlowMap.begin(); it != m_addressToControlFlowMap.end(); it++)
    {
        if (it->second->Type == CREF_FROM)
        {
            BOOL bHasOnlyOneChild = FALSE;
            if (lastIt != m_addressToControlFlowMap.end())
            {
                if (lastIt->first == it->first)
                {
                    NumberOfChildren++;
                }
                else
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format("Number Of Children for %x  = %u")
                        % lastIt->first
                        % NumberOfChildren;

                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;

                    multimap <va_t, PControlFlow>::iterator nextIt = it;
                    nextIt++;
                    if (nextIt == m_addressToControlFlowMap.end())
                    {
                        lastIt = it;
                        bHasOnlyOneChild = TRUE;
                    }
                    NumberOfChildren = 1;
                }
            }
            if (bHasOnlyOneChild)
            {
                int numberOfParents = 0;
                for (childIt = m_addressToControlFlowMap.find(lastIt->second->Dst);
                    childIt != m_addressToControlFlowMap.end() && childIt->first == lastIt->second->Dst;
                    childIt++)
                {
                    if (childIt->second->Type == CREF_TO && childIt->second->Dst != lastIt->first)
                    {
                        BOOST_LOG_TRIVIAL(debug) << boost::format("Found %x -> %x") % childIt->second->Dst % childIt->first;
                        numberOfParents++;
                    }
                }
                if (numberOfParents == 0)
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format(" Found Mergable Nodes %x -> %x") % lastIt->first % lastIt->second->Dst;
                }
            }
            lastIt = it;
        }
    }
}

vector<va_t> BasicBlocks::GetAddresses()
{
    vector<va_t> addresses;
    for (auto& val : m_disassemblyHashMaps.addressRangeMap)
    {
        addresses.push_back(val.first);
    }
    return addresses;
}

PBasicBlock BasicBlocks::GetBasicBlock(va_t address)
{
    return m_pdisassemblyReader->ReadBasicBlock(address);
}

va_t BasicBlocks::GetStartAddress(va_t address)
{
    return m_pdisassemblyReader->ReadBlockStartAddress(address);
}

va_t BasicBlocks::GetEndAddress(va_t address)
{
    multimap<va_t, va_t>::iterator it = m_disassemblyHashMaps.addressRangeMap.find(address);

    if (it != m_disassemblyHashMaps.addressRangeMap.end())
    {
        return it->second;
    }
    return 0;
}

string BasicBlocks::GetSymbol(va_t address)
{
    for (multimap <va_t, string>::iterator it = m_disassemblyHashMaps.addressToSymbolMap.find(address);
        it != m_disassemblyHashMaps.addressToSymbolMap.end();
        it++
        )
    {
        return it->second;
    }

    return {};
}

string BasicBlocks::GetDisasmLines(unsigned long startAddress)
{
    return m_pdisassemblyReader->ReadDisasmLine(startAddress);
}

vector<va_t> BasicBlocks::GetCodeReferences(va_t address, int type)
{
    vector<va_t> addresses;
    multimap <va_t, PControlFlow>::iterator it;
    for (it = m_addressToControlFlowMap.find(address); it != m_addressToControlFlowMap.end(); it++)
    {
        if (it->first != address)
            break;

        if (it->second->Type == type)
        {
            addresses.push_back(it->second->Dst);
        }
    }

    return addresses;
}

vector<va_t> BasicBlocks::GetParents(va_t address)
{
    vector<va_t> parentAddresses;

    for (multimap<va_t, va_t>::iterator it = m_dstToSrcAddressMap.find(address); it != m_dstToSrcAddressMap.end() && it->first == address; it++)
    {
        parentAddresses.push_back(it->second);
    }

    return parentAddresses;
}

vector<va_t> BasicBlocks::GetCallTargets()
{
    vector<va_t> callTargets;

    for (auto& val : m_addressToControlFlowMap)
    {
        if (val.second->Type == CALL)
        {
            callTargets.push_back(val.second->Dst);
        }
    }

    return callTargets; 
}

vector<unsigned char> BasicBlocks::GetInstructionBytes(va_t address)
{
    char* p_instructionBytes = m_pdisassemblyReader->ReadInstructionBytes(address);

    if (p_instructionBytes)
    {
        return HexToBytes(p_instructionBytes);
    }
    return {};
}
InstructionHashMap *BasicBlocks::GetInstructionHashes()
{
    return &(m_disassemblyHashMaps.instructionHashMap);
}

void BasicBlocks::DumpBlockInfo(va_t blockAddress)
{
    int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };
    const char* type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };

    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        BOOST_LOG_TRIVIAL(info) << boost::format(" %s: ") % type_descriptions[i];
        vector<va_t> addresses = GetCodeReferences(blockAddress, types[i]);
        for (va_t address : addresses)
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format(" %x ") % address;
        }
    }
    vector<unsigned char> instructionHash = m_disassemblyHashMaps.instructionHashMap.GetInstructionHash(blockAddress);

    if (!instructionHash.empty())
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format(" instruction_hash: %s") % BytesToHexString(instructionHash).c_str();
    }
}
