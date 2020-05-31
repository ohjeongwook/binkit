#include "Utility.h"
#include "BasicBlocks.h"

const char* ControlFlowTypesStr[] = { "Call", "Cref From", "Cref To", "Dref From", "Dref To" };

BasicBlocks::BasicBlocks(DisassemblyReader* p_disassemblyReader, bool load)
{
    m_pdisassemblyReader = p_disassemblyReader;

    if (load)
    {
        Load();
    }
}

BasicBlocks::~BasicBlocks()
{
    m_disassemblyHashMaps.symbolMap.clear();

    for (auto& val : m_disassemblyHashMaps.addressToControlFlowMap)
    {
        if (val.second)
            delete val.second;
    }
    m_disassemblyHashMaps.addressToControlFlowMap.clear();
    m_disassemblyHashMaps.addressToInstructionHashMap.clear();
    m_disassemblyHashMaps.instructionHashMap.clear();
}

void BasicBlocks::Load(va_t functionAddress)
{
    char conditionStr[50] = { 0, };
    if (functionAddress)
    {
        int ret = _snprintf_s(conditionStr, _countof(conditionStr), _TRUNCATE, "AND FunctionAddress = '%d'", functionAddress);
    }
    m_pdisassemblyReader->ReadBasicBlockHashes(conditionStr, &m_disassemblyHashMaps);

    m_pdisassemblyReader->ReadControlFlow(m_disassemblyHashMaps.addressToControlFlowMap, functionAddress, true);
    for (auto& val : m_disassemblyHashMaps.addressToControlFlowMap)
    {
        if (val.second->Type == CREF_FROM)
        {
            m_disassemblyHashMaps.dstToSrcAddressMap.insert(pair<va_t, va_t>(val.second->Dst, val.first));
        }
    }
}

vector<va_t> BasicBlocks::GetAddresses()
{
    vector<va_t> addresses;
    for (auto& val : m_disassemblyHashMaps.addressToInstructionHashMap)
    {
        addresses.push_back(val.first);
    }

    return addresses;
}

va_t BasicBlocks::GetBasicBlockStart(va_t address)
{
    return m_pdisassemblyReader->ReadBlockStartAddress(address);
}

PBasicBlock BasicBlocks::GetBasicBlock(va_t address)
{
    return m_pdisassemblyReader->ReadBasicBlock(address);
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

string BasicBlocks::GetDisasmLines(unsigned long startAddress, unsigned long endAddress)
{
    return m_pdisassemblyReader->ReadDisasmLine(startAddress);
}

vector<va_t> BasicBlocks::GetCodeReferences(va_t address, int type)
{
    vector<va_t> addresses;
    multimap <va_t, PControlFlow>::iterator it;
    for (it = m_disassemblyHashMaps.addressToControlFlowMap.find(address); it != m_disassemblyHashMaps.addressToControlFlowMap.end(); it++)
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

    for (multimap<va_t, va_t>::iterator it = m_disassemblyHashMaps.dstToSrcAddressMap.find(address);
        it != m_disassemblyHashMaps.dstToSrcAddressMap.end() && it->first == address;
        it++
        )
    {
        parentAddresses.push_back(it->second);
    }

    return parentAddresses;
}

vector<va_t> BasicBlocks::GetCallTargets()
{
    vector<va_t> callTargets;

    for (auto& val : m_disassemblyHashMaps.addressToControlFlowMap)
    {
        if (val.second->Type == CALL)
        {
            callTargets.push_back(val.second->Dst);
        }
    }

    return callTargets; 
}

void BasicBlocks::MergeBlocks()
{
    multimap <va_t, PControlFlow>::iterator lastIt = m_disassemblyHashMaps.addressToControlFlowMap.end();
    multimap <va_t, PControlFlow>::iterator it;
    multimap <va_t, PControlFlow>::iterator childIt;

    int NumberOfChildren = 1;
    for (it = m_disassemblyHashMaps.addressToControlFlowMap.begin(); it != m_disassemblyHashMaps.addressToControlFlowMap.end(); it++)
    {
        if (it->second->Type == CREF_FROM)
        {
            BOOL bHasOnlyOneChild = FALSE;
            if (lastIt != m_disassemblyHashMaps.addressToControlFlowMap.end())
            {
                if (lastIt->first == it->first)
                {
                    NumberOfChildren++;
                }
                else
                {
                    LogMessage(10, __FUNCTION__, "%s:Number Of Children for %X  = %u\n",
                        __FUNCTION__,
                        lastIt->first,
                        NumberOfChildren);
                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;
                    multimap <va_t, PControlFlow>::iterator nextIt = it;
                    nextIt++;
                    if (nextIt == m_disassemblyHashMaps.addressToControlFlowMap.end())
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
                for (childIt = m_disassemblyHashMaps.addressToControlFlowMap.find(lastIt->second->Dst);
                    childIt != m_disassemblyHashMaps.addressToControlFlowMap.end() && childIt->first == lastIt->second->Dst;
                    childIt++)
                {
                    if (childIt->second->Type == CREF_TO && childIt->second->Dst != lastIt->first)
                    {
                        LogMessage(10, __FUNCTION__, "%s:Found %X -> %X\n",
                            __FUNCTION__,
                            childIt->second->Dst, childIt->first);
                        numberOfParents++;
                    }
                }
                if (numberOfParents == 0)
                {
                    LogMessage(10, __FUNCTION__, "%s: Found Mergable Nodes %X -> %X\n", __FUNCTION__, lastIt->first, lastIt->second->Dst);
                }
            }
            lastIt = it;
        }
    }
}

vector<unsigned char> BasicBlocks::GetInstructionHash(va_t address)
{
    if (m_disassemblyHashMaps.addressToInstructionHashMap.size() > 0)
    {
        multimap <va_t, vector<unsigned char>>::iterator it = m_disassemblyHashMaps.addressToInstructionHashMap.find(address);
        if (it != m_disassemblyHashMaps.addressToInstructionHashMap.end())
        {
            return it->second;
        }
    }
    else
    {
        char* p_instructionHashStr = m_pdisassemblyReader->ReadInstructionHash(address);

        if (p_instructionHashStr)
        {
            return HexToBytes(p_instructionHashStr);
        }
    }
    return {};
}

InstructionHashMap *BasicBlocks::GetInstructionHashes()
{
    return &(m_disassemblyHashMaps.instructionHashMap);
}

void BasicBlocks::RemoveFromInstructionHashHash(va_t address)
{
    vector<unsigned char> instructionHash;
    char* p_instructionHashStr = m_pdisassemblyReader->ReadInstructionHash(address);

    if (p_instructionHashStr)
    {
        instructionHash = HexToBytes(p_instructionHashStr);
    }

    for (multimap <vector<unsigned char>, va_t>::iterator it = m_disassemblyHashMaps.instructionHashMap.find(instructionHash);
        it != m_disassemblyHashMaps.instructionHashMap.end(); it++
    )
    {
        if (it->first != instructionHash)
            break;

        if (it->second == address)
        {
            m_disassemblyHashMaps.instructionHashMap.erase(it);
            break;
        }
    }
}

void BasicBlocks::DumpBlockInfo(va_t blockAddress)
{
    int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };
    const char* type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };

    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        LogMessage(10, __FUNCTION__, "%s: %s: ", __FUNCTION__, type_descriptions[i]);

        vector<va_t> addresses = GetCodeReferences(blockAddress, types[i]);
        for (va_t address : addresses)
        {
            LogMessage(10, __FUNCTION__, "%s: %X ", __FUNCTION__, address);
        }
        LogMessage(10, __FUNCTION__, "\n");
    }
    vector<unsigned char> instructionHash = GetInstructionHash(blockAddress);

    if (!instructionHash.empty())
    {
        LogMessage(10, __FUNCTION__, "%s: instruction_hash: %s\n", __FUNCTION__, BytesToHexString(instructionHash).c_str());
    }
}

void BasicBlocks::GenerateTwoLevelInstructionHash()
{
    /*
    multimap <unsigned char *, va_t>::iterator instructionHashMap_pIter;
    for (instructionHashMap_pIter = m_disassemblyHashMaps.instructionHashMap.begin();
        instructionHashMap_pIter != m_disassemblyHashMaps.instructionHashMap.end();
        instructionHashMap_pIter++)

    {
        if(m_disassemblyHashMaps.instructionHashMap.count(instructionHashMap_pIter->first)>1)
        {
            int addresses_number = 0;
            va_t *addresses = GetCodeReferences(instructionHashMap_pIter->second, CREF_FROM, &addresses_number);
            if(!addresses)
                addresses = GetCodeReferences(instructionHashMap_pIter->second, CREF_TO, NULL);
            if(addresses)
            {
                int TwoLevelInstructionHashLength = 0;
                TwoLevelInstructionHashLength += *(unsigned short *)instructionHashMap_pIter->first; //+
                multimap <va_t,  unsigned char *>::iterator addressToInstructionHashMap_Iter;
                for (int i = 0;i<addresses_number;i++)
                {
                    addressToInstructionHashMap_Iter = m_disassemblyHashMaps.addressToInstructionHashMap.find(addresses[i]);
                    if(addressToInstructionHashMap_Iter != m_disassemblyHashMaps.addressToInstructionHashMap.end())
                    {
                        TwoLevelInstructionHashLength += *(unsigned short *)addressToInstructionHashMap_Iter->second; //+
                    }
                }

                if(TwoLevelInstructionHashLength>0)
                {
                    unsigned char *TwoLevelInstructionHash = (unsigned char *)malloc(TwoLevelInstructionHashLength+sizeof(short));
                    if(TwoLevelInstructionHash)
                    {
                        *(unsigned short *)TwoLevelInstructionHash = TwoLevelInstructionHashLength;

                        int Offset = sizeof(short);
                        memcpy(TwoLevelInstructionHash+Offset, instructionHashMap_pIter->first+sizeof(short), *(unsigned short *)instructionHashMap_pIter->first);
                        Offset += *(unsigned short *)instructionHashMap_pIter->first;
                        for (int i = 0;i<addresses_number;i++)
                        {
                            addressToInstructionHashMap_Iter = m_disassemblyHashMaps.addressToInstructionHashMap.find(addresses[i]);
                            if(addressToInstructionHashMap_Iter != m_disassemblyHashMaps.addressToInstructionHashMap.end())
                            {
                                memcpy(TwoLevelInstructionHash+Offset, addressToInstructionHashMap_Iter->second+sizeof(short), *(unsigned short *)addressToInstructionHashMap_Iter->second);
                                Offset += *(unsigned short *)addressToInstructionHashMap_Iter->second;
                            }
                        }
                        m_disassemblyHashMaps.instructionHashMap.insert(InstructionHashAddress_Pair(TwoLevelInstructionHash, instructionHashMap_pIter->second));
                    }
                }
            }
        }
    }*/
}