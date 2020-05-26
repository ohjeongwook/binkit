#include "Functions.h"

Functions::Functions(DisassemblyReader* p_disassemblyReader, BasicBlocks* p_basicBlocks)
{
    m_pdisassemblyReader = p_disassemblyReader;
    m_pbasicBlocks = p_basicBlocks;
    Load();
}

Functions::~Functions()
{
    m_blockToFunction.clear();
    m_functionToBlock.clear();
}

vector<va_t> *Functions::GetAddresses()
{
    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> functionAddresses;

    m_pdisassemblyReader->ReadFunctionAddressMap(functionAddresses);
    for (va_t callTarget : m_pbasicBlocks->GetCallTargets())
    {
        if (functionAddresses.find(callTarget) == functionAddresses.end())
        {
            LogMessage(10, __FUNCTION__, "%s: Function %X (by Call Recognition)\n", __FUNCTION__, callTarget);
            functionAddresses.insert(callTarget);
        }
    }

    return new vector<va_t>(functionAddresses.begin(), functionAddresses.end());
}

void Functions::Load()
{
    int Count = 0;

    LogMessage(10, __FUNCTION__, "%s: ID = %d GetAddresses\n", __FUNCTION__);
    vector <va_t>* p_functionAddresses = GetAddresses();
    if (p_functionAddresses)
    {
        LogMessage(10, __FUNCTION__, "%s: Function %u entries\n", __FUNCTION__, p_functionAddresses->size());

        unordered_map<va_t, va_t> addresses;
        unordered_map<va_t, va_t> membershipHash;

        for (va_t functionAddress : *p_functionAddresses)
        {
            for (auto& block : GetFunctionBasicBlocks(functionAddress))
            {
                m_blockToFunction.insert(pair <va_t, va_t>(block.Start, functionAddress));

                if (addresses.find(block.Start) == addresses.end())
                {
                    addresses.insert(pair<va_t, va_t>(block.Start, (va_t)1));
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
                for(va_t parentAddress: m_pbasicBlocks->GetParents(val.first))
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = membershipHash.find(val.first);
                    LogMessage(10, __FUNCTION__, "Found parent for %X -> %X\n", val.first, parentAddress);

                    unordered_map<va_t, va_t>::iterator parent_membership_it = membershipHash.find(parentAddress);
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
                    va_t functionStartAddress = val.first;
                    m_functionAddresses.insert(functionStartAddress);
                    list <AddressRange> function_member_blocks = GetFunctionBasicBlocks(functionStartAddress);
                    unordered_map<va_t, va_t>::iterator function_start_membership_it = membershipHash.find(functionStartAddress);

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
                        m_blockToFunction.insert(pair <va_t, va_t>(addr, functionStartAddress));
                        LogMessage(10, __FUNCTION__, "\tAdding Block: %X Function: %X\n", addr, functionStartAddress);
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

        LogMessage(10, __FUNCTION__, "%s: m_blockToFunction %u entries\n", __FUNCTION__, m_blockToFunction.size());
    }
}


list <AddressRange> Functions::GetFunctionBasicBlocks(unsigned long functionAddress)
{
    list <AddressRange> addressRangeList;
    list <va_t> addressList;
    unordered_set <va_t> checkedAddresses;
    addressList.push_back(functionAddress);

    AddressRange addressRange;
    addressRange.Start = functionAddress;
    PBasicBlock pBasicBlock = m_pbasicBlocks->GetBasicBlock(functionAddress);
    addressRange.End = pBasicBlock->EndAddress;
    addressRangeList.push_back(addressRange);

    checkedAddresses.insert(functionAddress);

    for (va_t currentAddress : addressList)
    {
        vector<va_t> addresses = m_pbasicBlocks->GetCodeReferences(currentAddress, CREF_FROM);
        for (va_t address : addresses)
        {
            if (m_functionAddresses.find(address) != m_functionAddresses.end())
                continue;

            if (checkedAddresses.find(address) == checkedAddresses.end())
            {
                PBasicBlock pBasicBlock = m_pbasicBlocks->GetBasicBlock(address);
                addressRange.Start = address;
                addressRange.End = pBasicBlock->EndAddress;
                addressRangeList.push_back(addressRange);

                checkedAddresses.insert(address);
                addressList.push_back(address);
            }
        }
    }

    return addressRangeList;
}

BOOL Functions::FixFunctionAddresses()
{
    BOOL is_fixed = FALSE;
    LogMessage(10, __FUNCTION__, "%s", __FUNCTION__);
    Load();

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->BeginTransaction();

    for (auto& val : m_blockToFunction)
    {
        //startAddress: val.first
        //FunctionAddress: val.second
        LogMessage(10, __FUNCTION__, "Updating BasicBlockTable Address = %X Function = %X\n", val.second, val.first);

        m_pdisassemblyReader->UpdateBasicBlock(val.first, val.second);
        is_fixed = TRUE;
    }

    if (m_pdisassemblyReader)
        m_pdisassemblyReader->EndTransaction();

    return is_fixed;
}

bool Functions::GetFunctionAddress(va_t address, va_t& functionAddress)
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

bool Functions::IsFunctionBlock(va_t block, va_t function)
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

multimap <va_t, va_t>* Functions::GetFunctionToBlock()
{
    LogMessage(10, __FUNCTION__, "GetFunctionToBlock\n");
    return &m_functionToBlock;
}
