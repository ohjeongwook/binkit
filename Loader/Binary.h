#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"

using namespace std;
using namespace stdext;

class Binary
{
private:
    int m_fileID;

    DisassemblyReader* m_pdisassemblyReader;

public:
    Binary(DisassemblyReader* DisassemblyReader = NULL);
    ~Binary();
    void SetFileID(int FileID = 1);
    int GetFileID();
};
