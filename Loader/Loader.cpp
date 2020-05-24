#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include <string>
#include <unordered_set>

#include "Loader.h"
#include "Log.h"
#include "DisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

#define DEBUG_LEVEL 0

const char *MapInfoTypesStr[] = { "Call", "Cref From", "Cref To", "Dref From", "Dref To" };
int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };

Loader::Loader(DisassemblyReader *p_disassemblyReader) :
    m_disassemblyHashMaps(NULL),
    TargetFunctionAddress(0),
    m_OriginalFilePath(NULL),
    m_FileID(0)
{
    m_disassemblyHashMaps = new DisassemblyHashMaps;
    m_pdisassemblyReader = p_disassemblyReader;
}

Loader::~Loader()
{
    if (m_OriginalFilePath)
        free(m_OriginalFilePath);

    if (m_disassemblyHashMaps)
    {
        m_disassemblyHashMaps->symbol_map.clear();

        for (auto& val : m_disassemblyHashMaps->map_info_map)
        {
            if (val.second)
                delete val.second;
        }

        m_disassemblyHashMaps->map_info_map.clear();

        for (auto& val : m_disassemblyHashMaps->address_to_instruction_hash_map)
        {
            if (val.second)
            {
                free(val.second);
            }
        }
        m_disassemblyHashMaps->address_to_instruction_hash_map.clear();
        m_disassemblyHashMaps->instruction_hash_map.clear();

        delete m_disassemblyHashMaps;
    }
}

va_t *Loader::GetMappedAddresses(va_t address, int type, int *p_length)
{
    va_t *addresses = NULL;
    int current_size = 50;

    addresses = (va_t*)malloc(sizeof(va_t)  *current_size);
    int addresses_i = 0;

    multimap <va_t, PMapInfo> *p_map_info_map;

    if (m_disassemblyHashMaps && m_disassemblyHashMaps->map_info_map.size() > 0)
    {
        p_map_info_map = &m_disassemblyHashMaps->map_info_map;
    }
    else
    {
        p_map_info_map = new multimap <va_t, PMapInfo>();
        LoadMapInfo(p_map_info_map, address);
    }

    multimap <va_t, PMapInfo>::iterator map_info_map_pIter;

    for (map_info_map_pIter = p_map_info_map->find(address); map_info_map_pIter != p_map_info_map->end(); map_info_map_pIter++)
    {
        if (map_info_map_pIter->first != address)
            break;
        if (map_info_map_pIter->second->Type == type)
        {
            //map_info_map_pIter->second->Dst
            //TODO: add
            if (current_size < addresses_i + 2)
            {
                current_size += 50;
                addresses = (va_t*)realloc(addresses, sizeof(va_t)  *(current_size));
            }
            addresses[addresses_i] = map_info_map_pIter->second->Dst;
            addresses_i++;
            addresses[addresses_i] = NULL;
        }
    }

    if (!m_disassemblyHashMaps)
    {
        p_map_info_map->clear();
        free(p_map_info_map);
    }

    if (p_length)
        *p_length = addresses_i;
    if (addresses_i == 0)
    {
        free(addresses);
        addresses = NULL;
    }
    return addresses;
}


list <va_t> *Loader::GetFunctionAddresses()
{
    if (TargetFunctionAddress != 0)
    {
        list <va_t> *function_addresses = new list<va_t>;
        if (function_addresses)
        {
            function_addresses->push_back(TargetFunctionAddress);
        }

        return function_addresses;
    }

    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> function_address_hash;
    unordered_map <va_t, short> addresses;

    if (DoCrefFromCheck)
    {
        LogMessage(10, __FUNCTION__, "addresses.size() = %u\n", addresses.size());

        for (auto& val: m_disassemblyHashMaps->map_info_map)
        {
            LogMessage(10, __FUNCTION__, "%X-%X(%s) ", val.first, val.second->Dst, MapInfoTypesStr[val.second->Type]);
            if (val.second->Type == CREF_FROM)
            {
                unordered_map <va_t, short>::iterator iter = addresses.find(val.second->Dst);
                if (iter != addresses.end())
                {
                    iter->second = FALSE;
                }
            }
        }
        LogMessage(10, __FUNCTION__, "%s\n", __FUNCTION__);

        for (auto& val : m_disassemblyHashMaps->address_to_instruction_hash_map)
        {
            addresses.insert(pair<va_t, short>(val.first, DoCrefFromCheck ? TRUE : FALSE));
        }

        LogMessage(10, __FUNCTION__, "addresses.size() = %u\n", addresses.size());
        for (auto& val : addresses)
        {
            if (val.second)
            {
                LogMessage(10, __FUNCTION__, "%s: ID = %d Function %X\n", __FUNCTION__, m_FileID, val.first);
                function_address_hash.insert(val.first);
            }
        }
    }
    else
    {
        m_pdisassemblyReader->ReadFunctionAddressMap(m_FileID, function_address_hash);
    }

    if (DoCallCheck && m_disassemblyHashMaps)
    {
        for (auto& val : m_disassemblyHashMaps->map_info_map)
        {
            if (val.second->Type == CALL)
            {
                if (function_address_hash.find(val.second->Dst) == function_address_hash.end())
                {
                    LogMessage(10, __FUNCTION__, "%s: ID = %d Function %X (by Call Recognition)\n", __FUNCTION__, m_FileID, val.second->Dst);
                    function_address_hash.insert(val.second->Dst);
                }
            }
        }
    }

    list <va_t> *function_addresses = new list<va_t>;
    if (function_addresses)
    {
        for (auto& val : function_address_hash)
        {
            function_addresses->push_back(val);
            LogMessage(11, __FUNCTION__, "%s: ID = %d Function %X\n", __FUNCTION__, m_FileID, val);
        }

        LogMessage(10, __FUNCTION__, "%s: ID = %d Returns(%u entries)\n", __FUNCTION__, m_FileID, function_addresses->size());
    }
    return function_addresses;
}

#undef USE_LEGACY_MAP_FOR_ADDRESS_MAP
void Loader::RemoveFromInstructionHashHash(va_t address)
{
    unsigned char *InstructionHash = NULL;

    char *InstructionHashStr = m_pdisassemblyReader->ReadInstructionHash(m_FileID, address);

    if (InstructionHashStr)
    {
        InstructionHash = HexToBytesWithLengthAmble(InstructionHashStr);
    }

    if (InstructionHash)
    {
        multimap <unsigned char*, va_t, hash_compare_instruction_hash>::iterator instruction_hash_map_PIter;
        for (instruction_hash_map_PIter = m_disassemblyHashMaps->instruction_hash_map.find(InstructionHash);
            instruction_hash_map_PIter != m_disassemblyHashMaps->instruction_hash_map.end();
            instruction_hash_map_PIter++
            )
        {
            if (!IsEqualByteWithLengthAmble(instruction_hash_map_PIter->first, InstructionHash))
                break;
            if (instruction_hash_map_PIter->second == address)
            {
                m_disassemblyHashMaps->instruction_hash_map.erase(instruction_hash_map_PIter);
                break;
            }
        }
        free(InstructionHash);
    }
}

char *Loader::GetInstructionHashStr(va_t address)
{
    if (m_disassemblyHashMaps && m_disassemblyHashMaps->address_to_instruction_hash_map.size() > 0)
    {
        multimap <va_t, unsigned char*>::iterator address_to_instruction_hash_map_PIter = m_disassemblyHashMaps->address_to_instruction_hash_map.find(address);
        if (address_to_instruction_hash_map_PIter != m_disassemblyHashMaps->address_to_instruction_hash_map.end())
        {
            return BytesWithLengthAmbleToHex(address_to_instruction_hash_map_PIter->second);
        }
    }
    else
    {
        char *InstructionHashPtr = m_pdisassemblyReader->ReadInstructionHash(m_FileID, address);
        return InstructionHashPtr;
    }
    return NULL;
}

char *Loader::GetSymbol(va_t address)
{
    char *Name = m_pdisassemblyReader->ReadSymbol(m_FileID, address);
    return Name;
}

va_t Loader::GetBlockAddress(va_t address)
{
    return m_pdisassemblyReader->ReadBlockStartAddress(m_FileID, address);
}

void Loader::DumpBlockInfo(va_t block_address)
{
    int addresses_number;
    const char *type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };
    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        va_t *addresses = GetMappedAddresses(block_address, types[i], &addresses_number);
        if (addresses)
        {
            LogMessage(10, __FUNCTION__, "%s: ID = %d %s: ", __FUNCTION__, m_FileID, type_descriptions[i]);
            for (int j = 0; j < addresses_number; j++)
            {
                LogMessage(10, __FUNCTION__, "%s: ID = %d %X ", __FUNCTION__, m_FileID, addresses[j]);
            }
            LogMessage(10, __FUNCTION__, "\n");
        }
    }
    char *hex_str = GetInstructionHashStr(block_address);
    if (hex_str)
    {
        LogMessage(10, __FUNCTION__, "%s: ID = %d instruction_hash: %s\n", __FUNCTION__, m_FileID, hex_str);
        free(hex_str);
    }
}

const char *GetAnalysisDataTypeStr(int type)
{
    static const char *Types[] = { "BASIC_BLOCK", "MAP_INFO", "FILE_INFO", "END_OF_DATA" };
    if (type < sizeof(Types) / sizeof(Types[0]))
        return Types[type];
    return "Unknown";
}

enum { TYPE_FILE_INFO, TYPE_ADDRESS_MAP, TYPE_ADDRESS_DISASSEMBLY_MAP, TYPE_INSTRUCTION_HASH_MAP, TYPE_TWO_LEVEL_INSTRUCTION_HASH_MAP, TYPE_address_to_instruction_hash_map, TYPE_NAME_MAP, TYPE_ADDRESS_NAME_MAP, TYPE_MAP_INFO_MAP };

const char *GetFileDataTypeStr(int type)
{
    static const char *Types[] = { "FILE_INFO", "ADDRESS_MAP", "ADDRESS_DISASSEMBLY_MAP", "INSTRUCTION_HASH_MAP", "TWO_LEVEL_INSTRUCTION_HASH_MAP", "address_to_instruction_hash_map", "NAME_MAP", "ADDRESS_NAME_MAP", "MAP_INFO_MAP" };
    if (type < sizeof(Types) / sizeof(Types[0]))
        return Types[type];
    return "Unknown";
}

char *Loader::GetOriginalFilePath()
{
    return m_OriginalFilePath;
}

BOOL Loader::LoadBasicBlock()
{
    if (m_disassemblyHashMaps->instruction_hash_map.size() == 0)
    {
        char conditionStr[50] = { 0, };
        if (TargetFunctionAddress)
        {
            _snprintf(conditionStr, sizeof(conditionStr) - 1, "AND FunctionAddress = '%d'", TargetFunctionAddress);
        }

        m_pdisassemblyReader->ReadBasicBlockInfo(m_FileID, conditionStr, m_disassemblyHashMaps);
    }
    return TRUE;
}

/*
FunctionAddress = 0 : Retrieve All Functions
    else			: Retrieve That Specific Function
*/

void Loader::SetFileID(int FileID)
{
    m_FileID = FileID;
}

void Loader::LoadMapInfo(multimap <va_t, PMapInfo> *p_map_info_map, va_t Address, bool IsFunction)
{
    if (Address == 0)
    {
        p_map_info_map = m_pdisassemblyReader->ReadMapInfo(m_FileID);
    }
    else
    {
        p_map_info_map = m_pdisassemblyReader->ReadMapInfo(m_FileID, Address, IsFunction);
    }

    BuildCodeReferenceMap(p_map_info_map);
}


void Loader::BuildCodeReferenceMap(multimap <va_t, PMapInfo> *p_map_info_map)
{
    for (auto& val : *p_map_info_map)
    {
        if (val.second->Type == CREF_FROM)
        {
            m_codeReferenceMap.insert(pair<va_t, va_t>(val.second->Dst, val.first));
        }
    }
}

BOOL Loader::Load()
{
    m_OriginalFilePath = m_pdisassemblyReader->GetOriginalFilePath(m_FileID);

    LoadBasicBlock();
    LoadMapInfo(&(m_disassemblyHashMaps->map_info_map), TargetFunctionAddress, true);

    return TRUE;
}

void Loader::AddAnalysisTargetFunction(va_t FunctionAddress)
{
    LogMessage(10, __FUNCTION__, "Add Analysis Target Function: %X\n", FunctionAddress);
    TargetFunctionAddress = FunctionAddress;
}

typedef struct {
    va_t address;
    va_t child_address;
} AddressPair;

void Loader::GenerateTwoLevelInstructionHash()
{
    /*
    multimap <unsigned char *, va_t, hash_compare_instruction_hash>::iterator instruction_hash_map_pIter;
    for (instruction_hash_map_pIter = m_disassemblyHashMaps->instruction_hash_map.begin();
        instruction_hash_map_pIter != m_disassemblyHashMaps->instruction_hash_map.end();
        instruction_hash_map_pIter++)

    {
        if(m_disassemblyHashMaps->instruction_hash_map.count(instruction_hash_map_pIter->first)>1)
        {
            int addresses_number = 0;
            va_t *addresses = GetMappedAddresses(instruction_hash_map_pIter->second, CREF_FROM, &addresses_number);
            if(!addresses)
                addresses = GetMappedAddresses(instruction_hash_map_pIter->second, CREF_TO, NULL);
            if(addresses)
            {
                int TwoLevelInstructionHashLength = 0;
                TwoLevelInstructionHashLength += *(unsigned short *)instruction_hash_map_pIter->first; //+
                multimap <va_t,  unsigned char *>::iterator address_to_instruction_hash_map_Iter;
                for (int i = 0;i<addresses_number;i++)
                {
                    address_to_instruction_hash_map_Iter = m_disassemblyHashMaps->address_to_instruction_hash_map.find(addresses[i]);
                    if(address_to_instruction_hash_map_Iter != m_disassemblyHashMaps->address_to_instruction_hash_map.end())
                    {
                        TwoLevelInstructionHashLength += *(unsigned short *)address_to_instruction_hash_map_Iter->second; //+
                    }
                }

                if(TwoLevelInstructionHashLength>0)
                {
                    unsigned char *TwoLevelInstructionHash = (unsigned char *)malloc(TwoLevelInstructionHashLength+sizeof(short));
                    if(TwoLevelInstructionHash)
                    {
                        *(unsigned short *)TwoLevelInstructionHash = TwoLevelInstructionHashLength;

                        int Offset = sizeof(short);
                        memcpy(TwoLevelInstructionHash+Offset, instruction_hash_map_pIter->first+sizeof(short), *(unsigned short *)instruction_hash_map_pIter->first);
                        Offset += *(unsigned short *)instruction_hash_map_pIter->first;
                        for (int i = 0;i<addresses_number;i++)
                        {
                            address_to_instruction_hash_map_Iter = m_disassemblyHashMaps->address_to_instruction_hash_map.find(addresses[i]);
                            if(address_to_instruction_hash_map_Iter != m_disassemblyHashMaps->address_to_instruction_hash_map.end())
                            {
                                memcpy(TwoLevelInstructionHash+Offset, address_to_instruction_hash_map_Iter->second+sizeof(short), *(unsigned short *)address_to_instruction_hash_map_Iter->second);
                                Offset += *(unsigned short *)address_to_instruction_hash_map_Iter->second;
                            }
                        }
                        m_disassemblyHashMaps->instruction_hash_map.insert(InstructionHashAddress_Pair(TwoLevelInstructionHash, instruction_hash_map_pIter->second));
                    }
                }
            }
        }
    }*/
}

void Loader::DumpDisassemblyHashMaps()
{
    if (m_disassemblyHashMaps)
    {
        LogMessage(10, __FUNCTION__, "OriginalFilePath = %s\n", m_disassemblyHashMaps->file_info.OriginalFilePath);
        LogMessage(10, __FUNCTION__, "ComputerName = %s\n", m_disassemblyHashMaps->file_info.ComputerName);
        LogMessage(10, __FUNCTION__, "UserName = %s\n", m_disassemblyHashMaps->file_info.UserName);
        LogMessage(10, __FUNCTION__, "CompanyName = %s\n", m_disassemblyHashMaps->file_info.CompanyName);
        LogMessage(10, __FUNCTION__, "FileVersion = %s\n", m_disassemblyHashMaps->file_info.FileVersion);
        LogMessage(10, __FUNCTION__, "FileDescription = %s\n", m_disassemblyHashMaps->file_info.FileDescription);
        LogMessage(10, __FUNCTION__, "InternalName = %s\n", m_disassemblyHashMaps->file_info.InternalName);
        LogMessage(10, __FUNCTION__, "ProductName = %s\n", m_disassemblyHashMaps->file_info.ProductName);
        LogMessage(10, __FUNCTION__, "ModifiedTime = %s\n", m_disassemblyHashMaps->file_info.ModifiedTime);
        LogMessage(10, __FUNCTION__, "MD5Sum = %s\n", m_disassemblyHashMaps->file_info.MD5Sum);

        LogMessage(10, __FUNCTION__, "instruction_hash_map = %u\n", m_disassemblyHashMaps->instruction_hash_map.size());
    }
}

char *Loader::GetDisasmLines(unsigned long StartAddress, unsigned long EndAddress)
{
    char *disasmLines = m_pdisassemblyReader->ReadDisasmLine(m_FileID, StartAddress);

    if (disasmLines)
    {
        LogMessage(10, __FUNCTION__, "DisasmLines = %s\n", disasmLines);
        return disasmLines;
    }
    return _strdup("");
}

string Loader::GetIdentity()
{
    return Identity;
}

PBasicBlock Loader::GetBasicBlock(va_t address)
{
    return m_pdisassemblyReader->ReadBasicBlock(m_FileID, address);
}

list <BLOCK> Loader::GetFunctionMemberBlocks(unsigned long function_address)
{
    list <BLOCK> block_list;

    if (m_disassemblyHashMaps)
    {
        list <va_t> address_list;
        unordered_set <va_t> checked_addresses;
        address_list.push_back(function_address);

        BLOCK block;
        block.Start = function_address;
        PBasicBlock pBasicBlock = GetBasicBlock(function_address);
        block.End = pBasicBlock->EndAddress;
        block_list.push_back(block);

        checked_addresses.insert(function_address);

        for (va_t currentAddress: address_list)
        {
            int addresses_number;
            va_t *p_addresses = GetMappedAddresses(currentAddress, CREF_FROM, &addresses_number);
            if (p_addresses && addresses_number > 0)
            {
                for (int i = 0; i < addresses_number; i++)
                {
                    va_t address = p_addresses[i];
                    if (address)
                    {
                        if (m_functionHeads.find(address) != m_functionHeads.end())
                            continue;

                        if (checked_addresses.find(address) == checked_addresses.end())
                        {
                            address_list.push_back(address);
                            block.Start = address;
                            PBasicBlock pBasicBlock = GetBasicBlock(address);
                            block.End = pBasicBlock->EndAddress;
                            block_list.push_back(block);

                            checked_addresses.insert(address);
                        }
                    }
                }
                free(p_addresses);
            }
        }
    }
    else
    {
        block_list = m_pdisassemblyReader->ReadFunctionMemberAddresses(m_FileID, function_address);
    }

    return block_list;
}

void Loader::MergeBlocks()
{
    multimap <va_t, PMapInfo>::iterator last_iter = m_disassemblyHashMaps->map_info_map.end();
    multimap <va_t, PMapInfo>::iterator iter;
    multimap <va_t, PMapInfo>::iterator child_iter;

    int NumberOfChildren = 1;
    for (iter = m_disassemblyHashMaps->map_info_map.begin();
        iter != m_disassemblyHashMaps->map_info_map.end();
        iter++
        )
    {
        if (iter->second->Type == CREF_FROM)
        {
            BOOL bHasOnlyOneChild = FALSE;
            if (last_iter != m_disassemblyHashMaps->map_info_map.end())
            {
                if (last_iter->first == iter->first)
                {
                    NumberOfChildren++;
                }
                else
                {
                    LogMessage(10, __FUNCTION__, "%s: ID = %d Number Of Children for %X  = %u\n",
                        __FUNCTION__, m_FileID,
                        last_iter->first,
                        NumberOfChildren);
                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;
                    multimap <va_t, PMapInfo>::iterator next_iter = iter;
                    next_iter++;
                    if (next_iter == m_disassemblyHashMaps->map_info_map.end())
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
                for (child_iter = m_disassemblyHashMaps->map_info_map.find(last_iter->second->Dst);
                    child_iter != m_disassemblyHashMaps->map_info_map.end() && child_iter->first == last_iter->second->Dst;
                    child_iter++)
                {
                    if (child_iter->second->Type == CREF_TO && child_iter->second->Dst != last_iter->first)
                    {
                        LogMessage(10, __FUNCTION__, "%s: ID = %d Found %X -> %X\n",
                            __FUNCTION__, m_FileID,
                            child_iter->second->Dst, child_iter->first);
                        NumberOfParents++;
                    }
                }
                if (NumberOfParents == 0)
                {
                    LogMessage(10, __FUNCTION__, "%s: ID = %d Found Mergable Nodes %X -> %X\n",
                        __FUNCTION__, m_FileID,
                        last_iter->first, last_iter->second->Dst);
                }
            }
            last_iter = iter;
        }
    }
}

int Loader::GetFileID()
{
    return m_FileID;
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
        LogMessage(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, m_FileID, argv[0], strtoul10(argv[0]), argv[1], strtoul10(argv[1]));
#endif
        AddressToFunctionMap->insert(pair <va_t, va_t>(strtoul10(argv[0]), strtoul10(argv[1])));
    }
    return 0;
}

void Loader::LoadBlockToFunction()
{
    int Count = 0;

    LogMessage(10, __FUNCTION__, "%s: ID = %d GetFunctionAddresses\n", __FUNCTION__);
    list <va_t> *function_addresses = GetFunctionAddresses();
    if (function_addresses)
    {
        LogMessage(10, __FUNCTION__, "%s: ID = %d Function %u entries\n", __FUNCTION__, m_FileID, function_addresses->size());

        unordered_map<va_t, va_t> addresses;
        unordered_map<va_t, va_t> membership_hash;

        for (va_t address : *function_addresses)
        {
            list <BLOCK> function_member_blocks = GetFunctionMemberBlocks(address);

            for (auto& val : function_member_blocks)
            {
                va_t addr = val.Start;
                m_blockToFunction.insert(pair <va_t, va_t>(addr, address));

                if (addresses.find(addr) == addresses.end())
                {
                    addresses.insert(pair<va_t, va_t>(addr, 1));
                }
                else
                {
                    addresses[addr] += 1;
                }

                if (membership_hash.find(addr) == membership_hash.end())
                {
                    membership_hash.insert(pair<va_t, va_t>(addr, address));
                }
                else
                {
                    membership_hash[addr] += address;
                }
            }
        }

        for (auto& val : addresses)
        {
            if (val.second > 1)
            {
                bool function_start = true;
                for (multimap<va_t, va_t>::iterator it2 = m_codeReferenceMap.find(val.first);
                    it2 != m_codeReferenceMap.end() && it2->first == val.first;
                    it2++
                    )
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = membership_hash.find(val.first);
                    va_t parent = it2->second;
                    LogMessage(10, __FUNCTION__, "Found parent for %X -> %X\n", val.first, parent);
                    unordered_map<va_t, va_t>::iterator parent_membership_it = membership_hash.find(parent);
                    if (current_membership_it != membership_hash.end() && parent_membership_it != membership_hash.end())
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
                    va_t function_start_addr = val.first;
                    m_functionHeads.insert(function_start_addr);
                    list <BLOCK> function_member_blocks = GetFunctionMemberBlocks(function_start_addr);
                    unordered_map<va_t, va_t>::iterator function_start_membership_it = membership_hash.find(function_start_addr);

                    for (list <BLOCK>::iterator it2 = function_member_blocks.begin();
                        it2 != function_member_blocks.end();
                        it2++
                        )
                    {
                        va_t addr = (*it2).Start;

                        unordered_map<va_t, va_t>::iterator current_membership_it = membership_hash.find(addr);

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
                        m_blockToFunction.insert(pair <va_t, va_t>(addr, function_start_addr));
                        LogMessage(10, __FUNCTION__, "\tAdding Block: %X Function: %X\n", addr, function_start_addr);
                    }
                }
            }
        }
        function_addresses->clear();
        delete function_addresses;

        for (auto& val : m_blockToFunction)
        {
            m_functionToBlock.insert(pair<va_t, va_t>(val.second, val.first));
        }

        LogMessage(10, __FUNCTION__, "%s: ID = %d m_blockToFunction %u entries\n", __FUNCTION__, m_FileID, m_blockToFunction.size());
    }
}

void Loader::ClearBlockToFunction()
{
    m_blockToFunction.clear();
    m_functionToBlock.clear();
}

BOOL Loader::FixFunctionAddresses()
{
    BOOL is_fixed = FALSE;
    LogMessage(10, __FUNCTION__, "%s", __FUNCTION__);
    LoadBlockToFunction();

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->BeginTransaction();

    for (auto& val : m_blockToFunction)
    {
        //StartAddress: val.first
        //FunctionAddress: val.second
        LogMessage(10, __FUNCTION__, "Updating BasicBlockTable Address = %X Function = %X\n", val.second, val.first);

        m_pdisassemblyReader->UpdateBasicBlock(m_FileID, val.first, val.second);
        is_fixed = TRUE;
    }

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->EndTransaction();

    ClearBlockToFunction();

    return is_fixed;
}

bool Loader::GetFunctionAddress(va_t address, va_t& function_address)
{
    multimap <va_t, va_t>::iterator it = m_blockToFunction.find(address);

    if (it != m_blockToFunction.end())
    {
        function_address = it->second;
        return true;
    }
    function_address = 0;
    return false;
}

bool Loader::FindBlockFunctionMatch(va_t block, va_t function)
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
