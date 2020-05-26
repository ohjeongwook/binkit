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

    for (auto& val : m_disassemblyHashMaps.addressToInstructionHashMap)
    {
        if (val.second)
        {
            free(val.second);
        }
    }
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

vector<va_t>* BasicBlocks::GetCodeReferences(va_t address, int type)
{
    vector<va_t>* p_addresses = new vector<va_t>;
    multimap <va_t, PControlFlow>::iterator it;
    for (it = m_disassemblyHashMaps.addressToControlFlowMap.find(address);
        it != m_disassemblyHashMaps.addressToControlFlowMap.end();
        it++
        )
    {
        if (it->first != address)
            break;

        if (it->second->Type == type)
        {
            p_addresses->push_back(it->second->Dst);
        }
    }

    return p_addresses;
}

void BasicBlocks::MergeBlocks()
{
    multimap <va_t, PControlFlow>::iterator last_iter = m_disassemblyHashMaps.addressToControlFlowMap.end();
    multimap <va_t, PControlFlow>::iterator iter;
    multimap <va_t, PControlFlow>::iterator child_iter;

    int NumberOfChildren = 1;
    for (iter = m_disassemblyHashMaps.addressToControlFlowMap.begin();
        iter != m_disassemblyHashMaps.addressToControlFlowMap.end();
        iter++
        )
    {
        if (iter->second->Type == CREF_FROM)
        {
            BOOL bHasOnlyOneChild = FALSE;
            if (last_iter != m_disassemblyHashMaps.addressToControlFlowMap.end())
            {
                if (last_iter->first == iter->first)
                {
                    NumberOfChildren++;
                }
                else
                {
                    LogMessage(10, __FUNCTION__, "%s:Number Of Children for %X  = %u\n",
                        __FUNCTION__,
                        last_iter->first,
                        NumberOfChildren);
                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;
                    multimap <va_t, PControlFlow>::iterator nextIt = iter;
                    nextIt++;
                    if (nextIt == m_disassemblyHashMaps.addressToControlFlowMap.end())
                    {
                        last_iter = iter;
                        bHasOnlyOneChild = TRUE;
                    }
                    NumberOfChildren = 1;
                }
            }
            if (bHasOnlyOneChild)
            {
                int numberOfParents = 0;
                for (child_iter = m_disassemblyHashMaps.addressToControlFlowMap.find(last_iter->second->Dst);
                    child_iter != m_disassemblyHashMaps.addressToControlFlowMap.end() && child_iter->first == last_iter->second->Dst;
                    child_iter++)
                {
                    if (child_iter->second->Type == CREF_TO && child_iter->second->Dst != last_iter->first)
                    {
                        LogMessage(10, __FUNCTION__, "%s:Found %X -> %X\n",
                            __FUNCTION__,
                            child_iter->second->Dst, child_iter->first);
                        numberOfParents++;
                    }
                }
                if (numberOfParents == 0)
                {
                    LogMessage(10, __FUNCTION__, "%s: Found Mergable Nodes %X -> %X\n",
                        __FUNCTION__, 
                        last_iter->first, last_iter->second->Dst);
                }
            }
            last_iter = iter;
        }
    }
}

string BasicBlocks::GetInstructionHashStr(va_t address)
{
    if (m_disassemblyHashMaps.addressToInstructionHashMap.size() > 0)
    {
        multimap <va_t, unsigned char*>::iterator it = m_disassemblyHashMaps.addressToInstructionHashMap.find(address);
        if (it != m_disassemblyHashMaps.addressToInstructionHashMap.end())
        {
            return BytesWithLengthAmbleToHex(it->second);
        }
    }
    else
    {
        return m_pdisassemblyReader->ReadInstructionHash(address);
    }
    return {};
}

void BasicBlocks::RemoveFromInstructionHashHash(va_t address)
{
    unsigned char* p_instructionHash = NULL;
    char* p_instructionHashStr = m_pdisassemblyReader->ReadInstructionHash(address);

    if (p_instructionHashStr)
    {
        p_instructionHash = HexToBytesWithLengthAmble(p_instructionHashStr);
    }

    if (p_instructionHash)
    {
        multimap <unsigned char*, va_t, hash_compare_instruction_hash>::iterator it;
        for (it = m_disassemblyHashMaps.instructionHashMap.find(p_instructionHash);
            it != m_disassemblyHashMaps.instructionHashMap.end();
            it++
            )
        {
            if (!IsEqualByteWithLengthAmble(it->first, p_instructionHash))
                break;
            if (it->second == address)
            {
                m_disassemblyHashMaps.instructionHashMap.erase(it);
                break;
            }
        }
        free(p_instructionHash);
    }
}

void BasicBlocks::DumpBlockInfo(va_t blockAddress)
{
    int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };
    const char* type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };

    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        LogMessage(10, __FUNCTION__, "%s: %s: ", __FUNCTION__, type_descriptions[i]);

        vector<va_t>* p_addresses = GetCodeReferences(blockAddress, types[i]);
        for (va_t address : *p_addresses)
        {
            LogMessage(10, __FUNCTION__, "%s: %X ", __FUNCTION__, address);
        }
        LogMessage(10, __FUNCTION__, "\n");
    }
    string hexString = GetInstructionHashStr(blockAddress);
    if (!hexString.empty())
    {
        LogMessage(10, __FUNCTION__, "%s: instruction_hash: %s\n", __FUNCTION__, hexString.c_str());
    }
}

void BasicBlocks::GenerateTwoLevelInstructionHash()
{
    /*
    multimap <unsigned char *, va_t, hash_compare_instruction_hash>::iterator instructionHashMap_pIter;
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