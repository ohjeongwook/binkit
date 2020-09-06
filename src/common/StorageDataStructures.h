#pragma once
#include "windows.h"
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <vector>

using namespace std;
using namespace stdext;

typedef int va_t;
#define strtoul10(X) strtoul(X, NULL, 10)

enum { SEND_ANALYSIS_DATA, UNINDENTIFIED_ADDR, MATCHED_ADDR, SHOW_DATA, SHOW_MATCH_ADDR, JUMP_TO_ADDR, GET_DISASM_LINES, COLOR_ADDRESS, GET_INPUT_NAME, MODIFIED_ADDR };

//DISASM_LINES,INSTRUCTION_HASH_INFO,NAME_INFO
enum { UNKNOWN_BLOCK, FUNCTION_BLOCK };

enum {
    CALL,       // 0: 
    CREF_FROM,  // 1:
    CREF_TO,    // 2: no
    DREF_FROM,  // 3: 
    DREF_TO,    // 4:
    CALLED      // 5: no
};

static const char* SubTypeStr[] = {
    "Call",
    "Cref From",
    "Cref To",
    "Call",
    "Dref From",
    "Dref To"
};

enum { BASIC_BLOCK, MAP_INFO, FILE_INFO, END_OF_DATA, DISASM_LINES, INPUT_NAME };

typedef struct _BinaryMetaData_
{
    int FileID;
    TCHAR OriginalFilePath[MAX_PATH + 1];
    string MD5;
    string SHA256;
    unsigned long long ImageBase;
} BinaryMetaData,  *PBinaryMetaData;

typedef struct _BasicBlock_ {
    va_t StartAddress;
    va_t EndAddress;
    char Flag; //Flag_t
    va_t FunctionAddress;
    char BlockType; // FUNCTION, UNKNOWN
    string Name;
    string InstructionHash;
    string InstructionBytes;
    string DisasmLines;
} BasicBlock,  *PBasicBlock;

typedef struct
{
    va_t Start;
    va_t End;
} AddressRange;

class ControlFlow {
public:
    unsigned char Type;
    va_t Src;
    va_t Dst;
};

typedef ControlFlow* PControlFlow;
typedef pair <va_t, PControlFlow> AddressPControlFlowPair;
