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
    m_pbasicBlocks(NULL),
    m_pfunctions(NULL)
{
}

Binary::~Binary()
{
}

void Binary::Open(string databaseFileName, int fileID)
{
    m_fileId = fileID;
    SQLiteDisassemblyReader* p_sqliteDisassemblyReader = new SQLiteDisassemblyReader(databaseFileName);
    m_pdisassemblyReader = (DisassemblyReader *)p_sqliteDisassemblyReader;
    m_pdisassemblyReader->SetFileID(m_fileId);
}

int Binary::GetFileID()
{
    return m_fileId;
}

BasicBlocks* Binary::GetBasicBlocks()
{
    if (!m_pbasicBlocks)
    {
        m_pbasicBlocks = new BasicBlocks(m_pdisassemblyReader, true);
    }
    return m_pbasicBlocks;
}

Functions* Binary::GetFunctions()
{
    if (!m_pfunctions)
    {
        if (!m_pbasicBlocks)
        {
            GetBasicBlocks();
        }
        m_pfunctions = new Functions(m_pdisassemblyReader, m_pbasicBlocks);
    }
    return m_pfunctions;
}
