#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "Binary.h"
#include "DisassemblyReader.h"
#include "SQLiteDisassemblyReader.h"
#include "Utility.h"
#include <iostream>
#include <boost/format.hpp> 
#include <boost/log/trivial.hpp>

using namespace std;
using namespace stdext;

Binary::Binary(string databaseFileName, int fileID) :
    m_fileId(0),
    m_pbasicBlocks(NULL)
{
    Open(databaseFileName, fileID);
}

Binary::~Binary()
{
    m_basicBlockToFunction.clear();
}

void Binary::Open(string databaseFileName, int fileID)
{
    m_fileId = fileID;
    SQLiteDisassemblyReader* p_sqliteDisassemblyReader = new SQLiteDisassemblyReader(databaseFileName);
    m_pdisassemblyReader = (DisassemblyReader *)p_sqliteDisassemblyReader;
    m_pdisassemblyReader->SetFileID(m_fileId);

    m_pbasicBlocks = new BasicBlocks(m_pdisassemblyReader, true);
    LoadFunctionAddressMap();
}

int Binary::GetFileID()
{
    return m_fileId;
}

string Binary::GetMD5()
{
    return m_pdisassemblyReader->GetMD5();
}

unsigned long long Binary::GetImageBase()
{
    return m_pdisassemblyReader->GetImageBase();
}

BasicBlocks* Binary::GetBasicBlocks()
{
    return m_pbasicBlocks;
}

void Binary::LoadFunctionAddressMap()
{
    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> functionAddresses;

    m_pdisassemblyReader->ReadFunctionAddressMap(functionAddresses);
    for (va_t callTarget : m_pbasicBlocks->GetCallTargets())
    {
        if (functionAddresses.find(callTarget) == functionAddresses.end())
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format("Binary::LoadFunctionAddressMap: %x - call reference") % callTarget;
            functionAddresses.insert(callTarget);
        }
    }

    for (va_t functionAddress : functionAddresses)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("Binary::LoadFunctionAddressMap: %x") % functionAddress;
        Function* p_function = new Function(m_pbasicBlocks, functionAddress);
        m_functions.push_back(p_function);
        m_functionAddressMap.insert(pair<va_t, Function*>(functionAddress, p_function));
    }

    BOOST_LOG_TRIVIAL(info) << boost::format("Function %u entries") % functionAddresses.size();
}

void Binary::LoadBasicBlockToFunctionMap()
{
    unordered_map<va_t, va_t> basicBlockAddresses;
    unordered_map<va_t, va_t> basicBlockFunctionHashes;

    for (Function* p_function : m_functions)
    {
        for (va_t address : p_function->GetBasicBlocks())
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format("Binary::LoadBasicBlockToFunctionMap basic block: %x function: %x") % address % p_function->GetAddress();
            m_basicBlockToFunction.insert(pair<va_t, va_t>(address, p_function->GetAddress()));
            if (basicBlockAddresses.find(address) == basicBlockAddresses.end())
            {
                basicBlockAddresses.insert(pair<va_t, va_t>(address, (va_t)1));
            }
            else
            {
                basicBlockAddresses[address] += 1;
            }

            if (basicBlockFunctionHashes.find(address) == basicBlockFunctionHashes.end())
            {
                basicBlockFunctionHashes.insert(pair<va_t, va_t>(address, p_function->GetAddress()));
            }
            else
            {
                basicBlockFunctionHashes[address] += p_function->GetAddress();
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
            BOOST_LOG_TRIVIAL(debug) << boost::format("Binary::LoadBasicBlockToFunctionMap found parent for %x -> %x") % val.first % parentAddress;
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

        /*BOOST_LOG_TRIVIAL(debug) << boost::format("    Multiple function membership: %x (%d) %s") % val.first % val.second % isFunctionStart ? "Possible Head" : "Member";
        if (isFunctionStart)
        {
            va_t functionStartAddress = val.first;
            unordered_map<va_t, va_t>::iterator isFunctionStart_membership_it = basicBlockFunctionHashes.find(functionStartAddress);
            multimap <va_t, Function*>::iterator it = m_functionAddressMap.find(functionStartAddress);

            if (it != m_functionAddressMap.end())
            {
                for (va_t address : it->second->GetBasicBlocks())
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = basicBlockFunctionHashes.find(address);

                    if (current_membership_it == basicBlockFunctionHashes.end() || isFunctionStart_membership_it->second != current_membership_it->second)
                        continue;

                    for (multimap <va_t, va_t>::iterator a2f_it = m_basicBlockToFunction.find(address);
                        a2f_it != m_basicBlockToFunction.end() && a2f_it->first == address;
                        a2f_it++
                    )
                    {
                        BOOST_LOG_TRIVIAL(debug) << boost::format("\tRemoving Basic Block: %x From Function: %x") % a2f_it->first % a2f_it->second;
                        a2f_it = m_basicBlockToFunction.erase(a2f_it);
                        if (a2f_it == m_basicBlockToFunction.end())
                        {
                            break;
                        }
                    }
                    m_basicBlockToFunction.insert(pair <va_t, va_t>(address, functionStartAddress));
                    BOOST_LOG_TRIVIAL(debug) << boost::format("Binary::LoadBasicBlockToFunctionMap Adding Block: %x Function: %x") % address % functionStartAddress;
                }
            }
        }*/
    }

    for (auto& val : m_basicBlockToFunction)
    {
        multimap <va_t, Function*>::iterator it = m_functionAddressMap.find(val.second);

        if (it != m_functionAddressMap.end())
        {
            it->second->AddBasicBlock(val.first);
        }
    }
    BOOST_LOG_TRIVIAL(info) << boost::format("m_basicBlockToFunction %u entries") % m_basicBlockToFunction.size();
}

bool Binary::UpdateFunctionAddressesInStorage()
{
    if (!m_pdisassemblyReader)
        return FALSE;

    return m_pdisassemblyReader->UpdateBasicBlockFunctions(m_basicBlockToFunction);
}

vector<Function*>* Binary::GetFunctions()
{
    return &m_functions;
}

Function *Binary::GetFunctionByStartAddress(va_t address)
{
    vector<Function*> functions;
    for (multimap <va_t, Function*>::iterator it = m_functionAddressMap.find(address); it != m_functionAddressMap.end(); it++)
    {
        if (it->first != address)
        {
            break;
        }
        return it->second;
    }
    return NULL;
}

vector<Function*> Binary::GetFunction(va_t address)
{
    vector<Function*> functions;
    for (multimap <va_t, Function*>::iterator it = m_functionAddressMap.find(address); it != m_functionAddressMap.end(); it++)
    {
        if (it->first != address)
        {
            break;
        }
        functions.push_back(it->second);
    }

    if (m_basicBlockToFunction.size() == 0)
    {
        LoadBasicBlockToFunctionMap();
    }

    for(multimap <va_t, va_t>::iterator it = m_basicBlockToFunction.find(address); it != m_basicBlockToFunction.end(); it++)
    {
        if (it->first != address)
        {
            break;
        }
        multimap <va_t, Function*>::iterator fuction_it = m_functionAddressMap.find(it->second);
        if (fuction_it != m_functionAddressMap.end())
        {
            functions.push_back(fuction_it->second);
        }
    }
    return functions;
}

bool Binary::IsInFunction(va_t basicBlockAddress, va_t functionAddress)
{
    for (multimap <va_t, va_t>::iterator it = m_basicBlockToFunction.find(basicBlockAddress); it != m_basicBlockToFunction.end() && it->first == basicBlockAddress; it++)
    {
        if (it->second == functionAddress)
        {
            return true;
        }
    }
    return false;
}
