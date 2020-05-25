#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "Binary.h"
#include "DisassemblyReader.h"
#include "SQLiteDisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

Binary::Binary() :
    m_fileId(0)
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

void Binary::LoadBasicBlocks()
{
    m_basicBlocks.Load();
}
