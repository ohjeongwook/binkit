#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "Binary.h"
#include "DisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

#define DEBUG_LEVEL 0

Binary::Binary(DisassemblyReader* p_disassemblyReader) :
    m_originalFilePath(NULL),
    m_fileID(0)
{
    m_pdisassemblyReader = p_disassemblyReader;
}

Binary::~Binary()
{
}

string Binary::GetOriginalFilePath()
{
    return m_originalFilePath;
}

/*
FunctionAddress = 0 : Retrieve All Functions
    else			: Retrieve That Specific Function
*/

void Binary::SetFileID(int fileID)
{
    m_fileID = fileID;
    m_pdisassemblyReader->SetFileID(m_fileID);
    m_originalFilePath = m_pdisassemblyReader->GetOriginalFilePath();    
}

int Binary::GetFileID()
{
    return m_fileID;
}

