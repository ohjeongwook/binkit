#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include <string>
#include <unordered_set>
#include <vector>

#include "Loader.h"
#include "Log.h"
#include "DisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

#define DEBUG_LEVEL 0

const char *ControlFlowTypesStr[] = { "Call", "Cref From", "Cref To", "Dref From", "Dref To" };
int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };

Loader::Loader(DisassemblyReader *p_disassemblyReader) :
    m_originalFilePath(NULL),
    m_fileID(0)
{
    m_pdisassemblyReader = p_disassemblyReader;
}

Loader::~Loader()
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

vector<va_t> *Loader::GetCodeReferences(va_t address, int type)
{
    vector<va_t> *p_addresses = new vector<va_t>;
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

vector<va_t> *Loader::GetFunctionAddresses()
{
    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> functionAddresses;

    m_pdisassemblyReader->ReadFunctionAddressMap(m_fileID, functionAddresses);

    for (auto& val : m_disassemblyHashMaps.addressToControlFlowMap)
    {
        if (val.second->Type == CALL)
        {
            if (functionAddresses.find(val.second->Dst) == functionAddresses.end())
            {
                LogMessage(10, __FUNCTION__, "%s: ID = %d Function %X (by Call Recognition)\n", __FUNCTION__, m_fileID, val.second->Dst);
                functionAddresses.insert(val.second->Dst);
            }
        }
    }
 
    return new vector<va_t>(functionAddresses.begin(), functionAddresses.end());
}

char *Loader::GetInstructionHashStr(va_t address)
{
    if (m_disassemblyHashMaps.addressToInstructionHashMap.size() > 0)
    {
        multimap <va_t, unsigned char*>::iterator addressToInstructionHashMap_PIter = m_disassemblyHashMaps.addressToInstructionHashMap.find(address);
        if (addressToInstructionHashMap_PIter != m_disassemblyHashMaps.addressToInstructionHashMap.end())
        {
            return BytesWithLengthAmbleToHex(addressToInstructionHashMap_PIter->second);
        }
    }
    else
    {
        char *InstructionHashPtr = m_pdisassemblyReader->ReadInstructionHash(m_fileID, address);
        return InstructionHashPtr;
    }
    return NULL;
}

void Loader::RemoveFromInstructionHashHash(va_t address)
{
    unsigned char *p_instructionHash = NULL;
    char *p_instructionHashStr = m_pdisassemblyReader->ReadInstructionHash(m_fileID, address);

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

string Loader::GetSymbol(va_t address)
{
    return m_pdisassemblyReader->ReadSymbol(m_fileID, address);
}

va_t Loader::GetBasicBlockStart(va_t address)
{
    return m_pdisassemblyReader->ReadBlockStartAddress(m_fileID, address);
}

string Loader::GetOriginalFilePath()
{
    return m_originalFilePath;
}

BOOL Loader::LoadBasicBlock(va_t functionAddress)
{
    if (m_disassemblyHashMaps.instructionHashMap.size() == 0)
    {
        char conditionStr[50] = { 0, };
        if (functionAddress)
        {
            _snprintf(conditionStr, sizeof(conditionStr) - 1, "AND FunctionAddress = '%d'", functionAddress);
        }

        m_pdisassemblyReader->ReadBasicBlockHashes(m_fileID, conditionStr, &m_disassemblyHashMaps);
    }
    return TRUE;
}

/*
FunctionAddress = 0 : Retrieve All Functions
    else			: Retrieve That Specific Function
*/

void Loader::SetFileID(int fileID)
{
    m_fileID = fileID;
}

void Loader::LoadControlFlow(multimap <va_t, PControlFlow> *p_controlFlow, va_t address, bool isFunction)
{
    if (address == 0)
    {
        p_controlFlow = m_pdisassemblyReader->ReadControlFlow(m_fileID);
    }
    else
    {
        p_controlFlow = m_pdisassemblyReader->ReadControlFlow(m_fileID, address, isFunction);
    }
}

BOOL Loader::Load(va_t functionAddress)
{
    m_originalFilePath = m_pdisassemblyReader->GetOriginalFilePath(m_fileID);

    LoadBasicBlock(functionAddress);
    LoadControlFlow(&(m_disassemblyHashMaps.addressToControlFlowMap), functionAddress, true);

    for (auto& val : m_disassemblyHashMaps.addressToControlFlowMap)
    {
        if (val.second->Type == CREF_FROM)
        {
            m_disassemblyHashMaps.dstToSrcAddressMap.insert(pair<va_t, va_t>(val.second->Dst, val.first));
        }
    }    
    return TRUE;
}


void Loader::GenerateTwoLevelInstructionHash()
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

string Loader::GetDisasmLines(unsigned long startAddress, unsigned long endAddress)
{
    return m_pdisassemblyReader->ReadDisasmLine(m_fileID, startAddress);
}

string Loader::GetIdentity()
{
    return Identity;
}

PBasicBlock Loader::GetBasicBlock(va_t address)
{
    return m_pdisassemblyReader->ReadBasicBlock(m_fileID, address);
}

list <AddressRange> Loader::GetFunctionBasicBlocks(unsigned long functionAddress)
{
    list <AddressRange> addressRangeList;
    list <va_t> addressList;
    unordered_set <va_t> checkedAddresses;
    addressList.push_back(functionAddress);

    AddressRange addressRange;
    addressRange.Start = functionAddress;
    PBasicBlock pBasicBlock = GetBasicBlock(functionAddress);
    addressRange.End = pBasicBlock->EndAddress;
    addressRangeList.push_back(addressRange);

    checkedAddresses.insert(functionAddress);

    for (va_t currentAddress: addressList)
    {
        vector<va_t> *p_addresses = GetCodeReferences(currentAddress, CREF_FROM);
        for(va_t address : *p_addresses)
        {
            if (m_functionHeads.find(address) != m_functionHeads.end())
                continue;

            if (checkedAddresses.find(address) == checkedAddresses.end())
            {
                PBasicBlock pBasicBlock = GetBasicBlock(address);
                addressRange.Start = address;                
                addressRange.End = pBasicBlock->EndAddress;
                addressRangeList.push_back(addressRange);

                checkedAddresses.insert(address);
                addressList.push_back(address);
            }
        }
        delete p_addresses;
    }

    return addressRangeList;
}

void Loader::MergeBlocks()
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
                    LogMessage(10, __FUNCTION__, "%s: ID = %d Number Of Children for %X  = %u\n",
                        __FUNCTION__, m_fileID,
                        last_iter->first,
                        NumberOfChildren);
                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;
                    multimap <va_t, PControlFlow>::iterator next_iter = iter;
                    next_iter++;
                    if (next_iter == m_disassemblyHashMaps.addressToControlFlowMap.end())
                    {
                        last_iter = iter;
                        bHasOnlyOneChild = TRUE;
                    }
                    NumberOfChildren = 1;
                }
            }
            if (bHasOnlyOneChild)
            {
                int NumberOfParents = 0;
                for (child_iter = m_disassemblyHashMaps.addressToControlFlowMap.find(last_iter->second->Dst);
                    child_iter != m_disassemblyHashMaps.addressToControlFlowMap.end() && child_iter->first == last_iter->second->Dst;
                    child_iter++)
                {
                    if (child_iter->second->Type == CREF_TO && child_iter->second->Dst != last_iter->first)
                    {
                        LogMessage(10, __FUNCTION__, "%s: ID = %d Found %X -> %X\n",
                            __FUNCTION__, m_fileID,
                            child_iter->second->Dst, child_iter->first);
                        NumberOfParents++;
                    }
                }
                if (NumberOfParents == 0)
                {
                    LogMessage(10, __FUNCTION__, "%s: ID = %d Found Mergable Nodes %X -> %X\n",
                        __FUNCTION__, m_fileID,
                        last_iter->first, last_iter->second->Dst);
                }
            }
            last_iter = iter;
        }
    }
}

int Loader::GetFileID()
{
    return m_fileID;
}

multimap <va_t, va_t> *Loader::GetFunctionToBlock()
{
    LogMessage(10, __FUNCTION__, "LoadFunctionMembersMap\n");
    return &m_functionToBlock;
}

static int ReadAddressToFunctionMapResultsCallback(void *arg, int argc, char **argv, char **names)
{
    unordered_map <va_t, va_t> *AddressToFunctionMap = (unordered_map <va_t, va_t>*)arg;
    if (AddressToFunctionMap)
    {
#if DEBUG_LEVEL > 1
        LogMessage(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, m_fileID, argv[0], strtoul10(argv[0]), argv[1], strtoul10(argv[1]));
#endif
        AddressToFunctionMap->insert(pair <va_t, va_t>(strtoul10(argv[0]), strtoul10(argv[1])));
    }
    return 0;
}

void Loader::LoadBlockFunctionMaps()
{
    int Count = 0;

    LogMessage(10, __FUNCTION__, "%s: ID = %d GetFunctionAddresses\n", __FUNCTION__);
    vector <va_t> *p_functionAddresses = GetFunctionAddresses();
    if (p_functionAddresses)
    {
        LogMessage(10, __FUNCTION__, "%s: ID = %d Function %u entries\n", __FUNCTION__, m_fileID, p_functionAddresses->size());

        unordered_map<va_t, va_t> addresses;
        unordered_map<va_t, va_t> membershipHash;

        for (va_t functionAddress : *p_functionAddresses)
        {
            for (auto& block : GetFunctionBasicBlocks(functionAddress))
            {
                m_blockToFunction.insert(pair <va_t, va_t>(block.Start, functionAddress));

                if (addresses.find(block.Start) == addresses.end())
                {
                    addresses.insert(pair<va_t, va_t>(block.Start, 1));
                }
                else
                {
                    addresses[block.Start] += 1;
                }

                if (membershipHash.find(block.Start) == membershipHash.end())
                {
                    membershipHash.insert(pair<va_t, va_t>(block.Start, functionAddress));
                }
                else
                {
                    membershipHash[block.Start] += functionAddress;
                }
            }
        }

        for (auto& val : addresses)
        {
            if (val.second > 1)
            {
                bool function_start = true;
                for (multimap<va_t, va_t>::iterator it2 = m_disassemblyHashMaps.dstToSrcAddressMap.find(val.first);
                    it2 != m_disassemblyHashMaps.dstToSrcAddressMap.end() && it2->first == val.first;
                    it2++
                    )
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = membershipHash.find(val.first);
                    va_t parent = it2->second;
                    LogMessage(10, __FUNCTION__, "Found parent for %X -> %X\n", val.first, parent);
                    unordered_map<va_t, va_t>::iterator parent_membership_it = membershipHash.find(parent);
                    if (current_membership_it != membershipHash.end() && parent_membership_it != membershipHash.end())
                    {
                        if (current_membership_it->second == parent_membership_it->second)
                        {
                            function_start = false;
                            break;
                        }
                    }
                }

                LogMessage(10, __FUNCTION__, "Multiple function membership: %X (%d) %s\n", val.first, val.second, function_start ? "Possible Head" : "Member");

                if (function_start)
                {
                    va_t function_startAddress = val.first;
                    m_functionHeads.insert(function_startAddress);
                    list <AddressRange> function_member_blocks = GetFunctionBasicBlocks(function_startAddress);
                    unordered_map<va_t, va_t>::iterator function_start_membership_it = membershipHash.find(function_startAddress);

                    for (list <AddressRange>::iterator it2 = function_member_blocks.begin();
                        it2 != function_member_blocks.end();
                        it2++
                        )
                    {
                        va_t addr = (*it2).Start;

                        unordered_map<va_t, va_t>::iterator current_membership_it = membershipHash.find(addr);

                        if (function_start_membership_it->second != current_membership_it->second)
                            continue;

                        for (multimap <va_t, va_t>::iterator a2f_it = m_blockToFunction.find(addr);
                            a2f_it != m_blockToFunction.end() && a2f_it->first == addr;
                            a2f_it++
                            )
                        {
                            LogMessage(10, __FUNCTION__, "\tRemoving Block: %X Function: %X\n", a2f_it->first, a2f_it->second);
                            a2f_it = m_blockToFunction.erase(a2f_it);
                        }
                        m_blockToFunction.insert(pair <va_t, va_t>(addr, function_startAddress));
                        LogMessage(10, __FUNCTION__, "\tAdding Block: %X Function: %X\n", addr, function_startAddress);
                    }
                }
            }
        }
        p_functionAddresses->clear();
        delete p_functionAddresses;

        for (auto& val : m_blockToFunction)
        {
            m_functionToBlock.insert(pair<va_t, va_t>(val.second, val.first));
        }

        LogMessage(10, __FUNCTION__, "%s: ID = %d m_blockToFunction %u entries\n", __FUNCTION__, m_fileID, m_blockToFunction.size());
    }
}

void Loader::ClearBlockFunctionMaps()
{
    m_blockToFunction.clear();
    m_functionToBlock.clear();
}

BOOL Loader::FixFunctionAddresses()
{
    BOOL is_fixed = FALSE;
    LogMessage(10, __FUNCTION__, "%s", __FUNCTION__);
    LoadBlockFunctionMaps();

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->BeginTransaction();

    for (auto& val : m_blockToFunction)
    {
        //startAddress: val.first
        //FunctionAddress: val.second
        LogMessage(10, __FUNCTION__, "Updating BasicBlockTable Address = %X Function = %X\n", val.second, val.first);

        m_pdisassemblyReader->UpdateBasicBlock(m_fileID, val.first, val.second);
        is_fixed = TRUE;
    }

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->EndTransaction();

    ClearBlockFunctionMaps();

    return is_fixed;
}

bool Loader::GetFunctionAddress(va_t address, va_t& functionAddress)
{
    multimap <va_t, va_t>::iterator it = m_blockToFunction.find(address);

    if (it != m_blockToFunction.end())
    {
        functionAddress = it->second;
        return true;
    }
    functionAddress = 0;
    return false;
}

bool Loader::IsFunctionBlock(va_t block, va_t function)
{
    for (multimap <va_t, va_t>::iterator it = m_blockToFunction.find(block); it != m_blockToFunction.end() && it->first == block; it++)
    {
        if (it->second == function)
        {
            return true;
        }
    }
    return false;
}

void Loader::DumpDisassemblyHashMaps()
{
    LogMessage(10, __FUNCTION__, "OriginalFilePath = %s\n", m_disassemblyHashMaps.file_info.OriginalFilePath);
    LogMessage(10, __FUNCTION__, "ComputerName = %s\n", m_disassemblyHashMaps.file_info.ComputerName);
    LogMessage(10, __FUNCTION__, "UserName = %s\n", m_disassemblyHashMaps.file_info.UserName);
    LogMessage(10, __FUNCTION__, "CompanyName = %s\n", m_disassemblyHashMaps.file_info.CompanyName);
    LogMessage(10, __FUNCTION__, "FileVersion = %s\n", m_disassemblyHashMaps.file_info.FileVersion);
    LogMessage(10, __FUNCTION__, "FileDescription = %s\n", m_disassemblyHashMaps.file_info.FileDescription);
    LogMessage(10, __FUNCTION__, "InternalName = %s\n", m_disassemblyHashMaps.file_info.InternalName);
    LogMessage(10, __FUNCTION__, "ProductName = %s\n", m_disassemblyHashMaps.file_info.ProductName);
    LogMessage(10, __FUNCTION__, "ModifiedTime = %s\n", m_disassemblyHashMaps.file_info.ModifiedTime);
    LogMessage(10, __FUNCTION__, "MD5Sum = %s\n", m_disassemblyHashMaps.file_info.MD5Sum);
    LogMessage(10, __FUNCTION__, "instructionHashMap = %u\n", m_disassemblyHashMaps.instructionHashMap.size());
}

void Loader::DumpBlockInfo(va_t blockAddress)
{
    const char *type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };
    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        LogMessage(10, __FUNCTION__, "%s: ID = %d %s: ", __FUNCTION__, m_fileID, type_descriptions[i]);

        vector<va_t> *p_addresses = GetCodeReferences(blockAddress, types[i]);
        for(va_t address : *p_addresses)
        {
            LogMessage(10, __FUNCTION__, "%s: ID = %d %X ", __FUNCTION__, m_fileID, address);
        }
        LogMessage(10, __FUNCTION__, "\n");
    }
    char *hexString = GetInstructionHashStr(blockAddress);
    if (hexString)
    {
        LogMessage(10, __FUNCTION__, "%s: ID = %d instruction_hash: %s\n", __FUNCTION__, m_fileID, hexString);
        free(hexString);
    }
}