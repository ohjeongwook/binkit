#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include <string>
#include <unordered_set>
#include <vector>

#include "Binaries.h"
#include "DisassemblyReader.h"
#include "Utility.h"

using namespace std;
using namespace stdext;

#define DEBUG_LEVEL 0

Binaries::Binaries(DisassemblyReader* p_disassemblyReader) :
    m_originalFilePath(NULL),
    m_fileID(0)
{
    m_pdisassemblyReader = p_disassemblyReader;
}

Binaries::~Binaries()
{
}

string Binaries::GetOriginalFilePath()
{
    return m_originalFilePath;
}

/*
FunctionAddress = 0 : Retrieve All Functions
    else			: Retrieve That Specific Function
*/

void Binaries::SetFileID(int fileID)
{
    m_fileID = fileID;
    m_originalFilePath = m_pdisassemblyReader->GetOriginalFilePath(m_fileID);
}

string Binaries::GetIdentity()
{
    return Identity;
}

int Binaries::GetFileID()
{
    return m_fileID;
}

