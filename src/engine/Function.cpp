#include "Function.h"

Function::Function(BasicBlocks* p_basicBlocks, va_t functionAddress)
{
    m_symbol = p_basicBlocks->GetSymbol(functionAddress);
    m_address = functionAddress;
    vector<va_t> newBasicBlockAddresses;

    m_basicBlockAddresses.insert(functionAddress);
    newBasicBlockAddresses.push_back(functionAddress);

    while (newBasicBlockAddresses.size() > 0)
    {
        vector<va_t> currentNewBasicBlockAddresses;
        for (va_t currentAddress : newBasicBlockAddresses)
        {
            vector<va_t> addresses = p_basicBlocks->GetCodeReferences(currentAddress, CREF_FROM);
            for (va_t address : addresses)
            {
                if (m_basicBlockAddresses.find(address) == m_basicBlockAddresses.end())
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format("Function::Function %x - %x") % functionAddress % address;
                    m_basicBlockAddresses.insert(address);
                    currentNewBasicBlockAddresses.push_back(address);
                }
            }
        }
        newBasicBlockAddresses = currentNewBasicBlockAddresses;
    }
}

void Function::AddBasicBlock(va_t functionAddress)
{
    if (m_basicBlockAddresses.find(functionAddress) == m_basicBlockAddresses.end())
    {
        m_basicBlockAddresses.insert(functionAddress);
    }
}

unordered_set<va_t> Function::GetBasicBlocks()
{
    return m_basicBlockAddresses;
}

va_t Function::GetAddress()
{
    return m_address;
}

string Function::GetSymbol()
{
    return m_symbol;
}
