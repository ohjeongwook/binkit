#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "Binary.h"
#include "DisassemblyReader.h"
#include "SQLiteDisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

Binary::Binary() :
    m_fileId(0),
    m_pbasicBlocks(NULL)
{
}

Binary::~Binary()
{
    m_basicBlockToFunctionAddresses.clear();
}

void Binary::Open(string databaseFileName, int fileID)
{
    m_fileId = fileID;
    SQLiteDisassemblyReader* p_sqliteDisassemblyReader = new SQLiteDisassemblyReader(databaseFileName);
    m_pdisassemblyReader = (DisassemblyReader *)p_sqliteDisassemblyReader;
    m_pdisassemblyReader->SetFileID(m_fileId);

    m_pbasicBlocks = new BasicBlocks(m_pdisassemblyReader, true);

    Load();
    UpdateFunctionAddressesInStorage();
}

int Binary::GetFileID()
{
    return m_fileId;
}

string Binary::GetMD5()
{
    return m_pdisassemblyReader->GetMD5();
}

BasicBlocks* Binary::GetBasicBlocks()
{
    return m_pbasicBlocks;
}

void Binary::Load()
{
    LogMessage(0, __FUNCTION__, "%s:\n", __FUNCTION__);

    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> functionAddresses;

    // Enumerate function addresses
    m_pdisassemblyReader->ReadFunctionAddressMap(functionAddresses);
    for (va_t callTarget : m_pbasicBlocks->GetCallTargets())
    {
        if (functionAddresses.find(callTarget) == functionAddresses.end())
        {
            LogMessage(0, __FUNCTION__, "%s: Function %X (by Call Recognition)\n", __FUNCTION__, callTarget);
            functionAddresses.insert(callTarget);
        }
    }

    // Build up m_functions, m_addressToFunctions
    for (va_t functionAddress : functionAddresses)
    {
        Function* p_function = new Function(m_pbasicBlocks, functionAddress);
        m_functions.push_back(p_function);
        m_addressToFunctions.insert(pair<va_t, Function*>(functionAddress, p_function));
    }

    LogMessage(0, __FUNCTION__, "%s: Function %u entries\n", __FUNCTION__, functionAddresses.size());

    unordered_map<va_t, va_t> basicBlockAddresses;
    unordered_map<va_t, va_t> basicBlockFunctionHashes;

    for (Function* p_function : m_functions)
    {
        for (va_t basicBlockAddress : p_function->GetBasicBlocks())
        {
            m_basicBlockToFunctionAddresses.insert(pair <va_t, va_t>(basicBlockAddress, p_function->GetAddress()));

            if (basicBlockAddresses.find(basicBlockAddress) == basicBlockAddresses.end())
            {
                basicBlockAddresses.insert(pair<va_t, va_t>(basicBlockAddress, (va_t)1));
            }
            else
            {
                basicBlockAddresses[basicBlockAddress] += 1;
            }

            if (basicBlockFunctionHashes.find(basicBlockAddress) == basicBlockFunctionHashes.end())
            {
                basicBlockFunctionHashes.insert(pair<va_t, va_t>(basicBlockAddress, p_function->GetAddress()));
            }
            else
            {
                basicBlockFunctionHashes[basicBlockAddress] += p_function->GetAddress();
            }
        }
    }

    for (auto& val : basicBlockAddresses)
    {
        if (val.second < 1)
        {
            continue;
        }

        bool isFunctionStart = true;
        for (va_t parentAddress : m_pbasicBlocks->GetParents(val.first))
        {
            unordered_map<va_t, va_t>::iterator it = basicBlockFunctionHashes.find(val.first);
            LogMessage(0, __FUNCTION__, "Found parent for %X -> %X\n", val.first, parentAddress);

            unordered_map<va_t, va_t>::iterator parent_membership_it = basicBlockFunctionHashes.find(parentAddress);
            if (it != basicBlockFunctionHashes.end() && parent_membership_it != basicBlockFunctionHashes.end())
            {
                if (it->second == parent_membership_it->second)
                {
                    isFunctionStart = false;
                    break;
                }
            }
        }

        LogMessage(0, __FUNCTION__, "Multiple function membership: %X (%d) %s\n", val.first, val.second, isFunctionStart ? "Possible Head" : "Member");

        if (isFunctionStart)
        {
            va_t functionStartAddress = val.first;
            unordered_map<va_t, va_t>::iterator isFunctionStart_membership_it = basicBlockFunctionHashes.find(functionStartAddress);
            multimap <va_t, Function*>::iterator it = m_addressToFunctions.find(functionStartAddress);

            if (it != m_addressToFunctions.end())
            {
                for (va_t address : it->second->GetBasicBlocks())
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = basicBlockFunctionHashes.find(address);

                    if (current_membership_it == basicBlockFunctionHashes.end() || isFunctionStart_membership_it->second != current_membership_it->second)
                        continue;

                    for (multimap <va_t, va_t>::iterator a2f_it = m_basicBlockToFunctionAddresses.find(address);
                        a2f_it != m_basicBlockToFunctionAddresses.end() && a2f_it->first == address;
                        a2f_it++
                        )
                    {
                        LogMessage(0, __FUNCTION__, "\tRemoving Block: %X Function: %X\n", a2f_it->first, a2f_it->second);
                        a2f_it = m_basicBlockToFunctionAddresses.erase(a2f_it);
                        if (a2f_it == m_basicBlockToFunctionAddresses.end())
                        {
                            break;
                        }
                    }
                    m_basicBlockToFunctionAddresses.insert(pair <va_t, va_t>(address, functionStartAddress));
                    LogMessage(0, __FUNCTION__, "\tAdding Block: %X Function: %X\n", address, functionStartAddress);
                }
            }
        }
    }


    for (auto& val : m_basicBlockToFunctionAddresses)
    {
        multimap <va_t, Function*>::iterator it = m_addressToFunctions.find(val.second);

        if (it != m_addressToFunctions.end())
        {
            it->second->AddBasicBlock(val.first);
        }
    }
    LogMessage(0, __FUNCTION__, "%s: m_basicBlockToFunctionAddresses %u entries\n", __FUNCTION__, m_basicBlockToFunctionAddresses.size());
}

bool Binary::UpdateFunctionAddressesInStorage()
{
    LogMessage(0, __FUNCTION__, "%s", __FUNCTION__);
    Load();

    if (!m_pdisassemblyReader)
        return FALSE;

    return m_pdisassemblyReader->UpdateBasicBlockFunctions(m_basicBlockToFunctionAddresses);
}

vector<Function*>* Binary::GetFunctions()
{
    return &m_functions;
}

Function* Binary::GetFunction(va_t address)
{
    multimap <va_t, Function*>::iterator it = m_addressToFunctions.find(address);

    if (it != m_addressToFunctions.end())
    {
        return it->second;
    }

    multimap <va_t, va_t>::iterator it2 = m_basicBlockToFunctionAddresses.find(address);

    if (it2 != m_basicBlockToFunctionAddresses.end())
    {
        multimap <va_t, Function*>::iterator it3 = m_addressToFunctions.find(it2->second);
        if (it3 != m_addressToFunctions.end())
        {
            return it3->second;
        }
    }
    return NULL;
}

bool Binary::IsInFunction(va_t basicBlockAddress, va_t functionAddress)
{
    for (multimap <va_t, va_t>::iterator it = m_basicBlockToFunctionAddresses.find(basicBlockAddress); it != m_basicBlockToFunctionAddresses.end() && it->first == basicBlockAddress; it++)
    {
        if (it->second == functionAddress)
        {
            return true;
        }
    }
    return false;
}
