#include "Function.h"

Function::Function(BasicBlocks* p_basicBlocks, va_t address)
{
    m_address = address;
    m_pbasicBlocks = p_basicBlocks;
    vector<va_t> newBasicBlockAddresses;

    m_basicBlockAddresses.insert(address);
    newBasicBlockAddresses.push_back(address);

    while (newBasicBlockAddresses.size() > 0)
    {
        vector<va_t> currentNewBasicBlockAddresses;
        for (va_t currentAddress : newBasicBlockAddresses)
        {
            vector<va_t> addresses = m_pbasicBlocks->GetCodeReferences(currentAddress, CREF_FROM);
            for (va_t address : addresses)
            {
                if (m_basicBlockAddresses.find(address) == m_basicBlockAddresses.end())
                {
                    m_basicBlockAddresses.insert(address);
                    currentNewBasicBlockAddresses.push_back(address);
                }
            }
        }

        newBasicBlockAddresses = currentNewBasicBlockAddresses;
    }
}

void Function::AddBasicBlock(va_t address)
{
    if (m_basicBlockAddresses.find(address) == m_basicBlockAddresses.end())
    {
        m_basicBlockAddresses.insert(address);
    }
}

va_t Function::GetAddress()
{
    return m_address;
}

unordered_set<va_t> Function::GetBasicBlocks()
{
    return m_basicBlockAddresses;
}

string Function::GetSymbol()
{
    return m_pbasicBlocks->GetSymbol(m_address);
}