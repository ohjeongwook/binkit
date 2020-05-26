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
    m_pfunctions(NULL)
{
}

Binary::~Binary()
{
}

void Binary::Open(string databaseFileName, int fileID)
{
    m_fileId = fileID;
    SQLiteDisassemblyReader* p_sqliteDisassemblyReader = new SQLiteDisassemblyReader();
    p_sqliteDisassemblyReader->Open(databaseFileName);

    m_pdisassemblyReader = (DisassemblyReader *)p_sqliteDisassemblyReader;
    m_pdisassemblyReader->SetFileID(m_fileId);
}

int Binary::GetFileID()
{
    return m_fileId;
}

BasicBlocks* Binary::LoadBasicBlocks()
{
    BasicBlocks *p_basicBlocks = new BasicBlocks(m_pdisassemblyReader);
    p_basicBlocks->Load();
    return p_basicBlocks;
}
