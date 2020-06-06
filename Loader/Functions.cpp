#include "Functions.h"

Functions::Functions(DisassemblyReader* p_disassemblyReader, BasicBlocks* p_basicBlocks)
{
    m_pdisassemblyReader = p_disassemblyReader;
    m_pbasicBlocks = p_basicBlocks;
    Load();
    UpdateFunctionAddressesInStorage();
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
            LogMessage(0, __FUNCTION__, "%s: Function %X (by Call Recognition)\n", __FUNCTION__, callTarget);
            functionAddresses.insert(callTarget);
        }
    }

    return new vector<va_t>(functionAddresses.begin(), functionAddresses.end());
}

void Functions::Load()
{
    int Count = 0;

    LogMessage(0, __FUNCTION__, "%s: ID = %d GetAddresses\n", __FUNCTION__);
    vector <va_t>* p_functionAddresses = GetAddresses();
    if (p_functionAddresses)
    {
        LogMessage(0, __FUNCTION__, "%s: Function %u entries\n", __FUNCTION__, p_functionAddresses->size());

        unordered_map<va_t, va_t> basicBlockAddresses;
        unordered_map<va_t, va_t> membershipHash;

        for (va_t functionAddress : *p_functionAddresses)
        {
            for (va_t basicBlockAddress : GetBasicBlocks(functionAddress))
            {
                m_blockToFunction.insert(pair <va_t, va_t>(basicBlockAddress, functionAddress));

                if (basicBlockAddresses.find(basicBlockAddress) == basicBlockAddresses.end())
                {
                    basicBlockAddresses.insert(pair<va_t, va_t>(basicBlockAddress, (va_t)1));
                }
                else
                {
                    basicBlockAddresses[basicBlockAddress] += 1;
                }

                if (membershipHash.find(basicBlockAddress) == membershipHash.end())
                {
                    membershipHash.insert(pair<va_t, va_t>(basicBlockAddress, functionAddress));
                }
                else
                {
                    membershipHash[basicBlockAddress] += functionAddress;
                }
            }
        }

        for (auto& val : basicBlockAddresses)
        {
            if (val.second > 1)
            {
                bool function_start = true;
                for(va_t parentAddress: m_pbasicBlocks->GetParents(val.first))
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = membershipHash.find(val.first);
                    LogMessage(0, __FUNCTION__, "Found parent for %X -> %X\n", val.first, parentAddress);

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

                LogMessage(0, __FUNCTION__, "Multiple function membership: %X (%d) %s\n", val.first, val.second, function_start ? "Possible Head" : "Member");

                if (function_start)
                {
                    va_t functionStartAddress = val.first;
                    m_functionAddresses.insert(functionStartAddress);
                    unordered_map<va_t, va_t>::iterator function_start_membership_it = membershipHash.find(functionStartAddress);

                    for(va_t address : GetBasicBlocks(functionStartAddress))
                    {
                        unordered_map<va_t, va_t>::iterator current_membership_it = membershipHash.find(address);

                        if (current_membership_it == membershipHash.end() || function_start_membership_it->second != current_membership_it->second)
                            continue;

                        for (multimap <va_t, va_t>::iterator a2f_it = m_blockToFunction.find(address);
                            a2f_it != m_blockToFunction.end() && a2f_it->first == address;
                            a2f_it++
                            )
                        {
                            LogMessage(0, __FUNCTION__, "\tRemoving Block: %X Function: %X\n", a2f_it->first, a2f_it->second);
                            a2f_it = m_blockToFunction.erase(a2f_it);
                        }
                        m_blockToFunction.insert(pair <va_t, va_t>(address, functionStartAddress));
                        LogMessage(0, __FUNCTION__, "\tAdding Block: %X Function: %X\n", address, functionStartAddress);
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

        LogMessage(0, __FUNCTION__, "%s: m_blockToFunction %u entries\n", __FUNCTION__, m_blockToFunction.size());
    }
}


vector<va_t> Functions::GetBasicBlocks(va_t functionAddress)
{
    vector<va_t> basicBlockAddresses;
    unordered_set <va_t> checkedAddresses;
    basicBlockAddresses.push_back(functionAddress);
    checkedAddresses.insert(functionAddress);
    vector<va_t> newBasicBlockAddresses;

    newBasicBlockAddresses.push_back(functionAddress);
    while (newBasicBlockAddresses.size() > 0)
    {
        vector<va_t> currentNewBasicBlockAddresses;
        for (va_t currentAddress : newBasicBlockAddresses)
        {
            vector<va_t> addresses = m_pbasicBlocks->GetCodeReferences(currentAddress, CREF_FROM);
            for (va_t address : addresses)
            {
                if (m_functionAddresses.find(address) != m_functionAddresses.end())
                    continue;

                if (checkedAddresses.find(address) == checkedAddresses.end())
                {
                    checkedAddresses.insert(address);
                    basicBlockAddresses.push_back(address);
                    currentNewBasicBlockAddresses.push_back(address);
                }
            }
        }

        newBasicBlockAddresses = currentNewBasicBlockAddresses;
    }

    return basicBlockAddresses;
}

bool Functions::UpdateFunctionAddressesInStorage()
{
    LogMessage(0, __FUNCTION__, "%s", __FUNCTION__);
    Load();

    if (!m_pdisassemblyReader)
        return FALSE;

    return m_pdisassemblyReader->UpdateBasicBlock(m_blockToFunction);
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

bool Functions::IsInFunction(va_t basicBlockAddress, va_t functionAddress)
{
    for (multimap <va_t, va_t>::iterator it = m_blockToFunction.find(basicBlockAddress); it != m_blockToFunction.end() && it->first == basicBlockAddress; it++)
    {
        if (it->second == functionAddress)
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
