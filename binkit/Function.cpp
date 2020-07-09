#include "Function.h"

Function::Function(va_t address)
{
    m_address = address;
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

vector<va_t> Function::GetBasicBlocks()
{
    vector<va_t> basicBlockAddresses;
    basicBlockAddresses.insert(basicBlockAddresses.end(), m_basicBlockAddresses.begin(), m_basicBlockAddresses.end());
    return basicBlockAddresses;
}
