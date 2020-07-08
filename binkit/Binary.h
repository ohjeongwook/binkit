#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <unordered_map>
#include <unordered_set>
#include <list>

#include "Structures.h"
#include "DisassemblyReader.h"
#include "BasicBlocks.h"
#include "Functions.h"

using namespace std;
using namespace stdext;

class Binary
{
private:
    int m_fileId;
    BasicBlocks* m_pbasicBlocks;
    Functions *m_pfunctions;

    DisassemblyReader* m_pdisassemblyReader;

public:
    Binary();
    ~Binary();
    void Open(string databaseFileName, int fileId = 0);
    int GetFileID();
    BasicBlocks* GetBasicBlocks();
    Functions* GetFunctions();
};
