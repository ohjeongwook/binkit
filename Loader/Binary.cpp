#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "Binary.h"
#include "DisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

Binary::Binary(DisassemblyReader* p_disassemblyReader) :
    m_fileID(0)
{
    m_pdisassemblyReader = p_disassemblyReader;
}

Binary::~Binary()
{
}

void Binary::SetFileID(int fileID)
{
    m_fileID = fileID;
    m_pdisassemblyReader->SetFileID(m_fileID);
}

int Binary::GetFileID()
{
    return m_fileID;
}

