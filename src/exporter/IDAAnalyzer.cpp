#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <unordered_set>
#include <vector>
#include <list>
#include <string>

#include "Utility.h"
#include "IDAAnalyzer.h"
#include "DisassemblyStorage.h"

using namespace std;
using namespace stdext;

int Debug = 1;

string GetFeatureStr(DWORD features)
{
    string FeatureStr = " ";
    if (features & CF_STOP)
        FeatureStr += "CF_STOP ";
    if (features & CF_CALL)
        FeatureStr += "CF_CALL ";
    if (features & CF_CHG1)
        FeatureStr += "CF_CHG1 ";
    if (features & CF_CHG2)
        FeatureStr += "CF_CHG2 ";
    if (features & CF_CHG3)
        FeatureStr += "CF_CHG3 ";
    if (features & CF_CHG4)
        FeatureStr += "CF_CHG4 ";
    if (features & CF_CHG5)
        FeatureStr += "CF_CHG5 ";
    if (features & CF_CHG6)
        FeatureStr += "CF_CHG6 ";
    if (features & CF_USE1)
        FeatureStr += "CF_USE1 ";
    if (features & CF_USE2)
        FeatureStr += "CF_USE2 ";
    if (features & CF_USE3)
        FeatureStr += "CF_USE3 ";
    if (features & CF_USE4)
        FeatureStr += "CF_USE4 ";
    if (features & CF_USE5)
        FeatureStr += "CF_USE5 ";
    if (features & CF_USE6)
        FeatureStr += "CF_USE6 ";
    if (features & CF_JUMP)
        FeatureStr += "CF_JUMP ";
    if (features & CF_SHFT)
        FeatureStr += "CF_SHFT ";
    if (features & CF_HLL)
        FeatureStr += "CF_HLL ";
    return FeatureStr;
}

#define CF_USE 1
#define CF_CHG 2

void GetFeatureBits(int itype, char *FeatureMap, int Size, insn_t insn)
{
    memset(FeatureMap, 0, Size);
    if (Size < sizeof(char) * 6)
        return;
    DWORD features = ph.instruc[itype].feature;
    if (features & CF_CHG1)
        FeatureMap[0] |= CF_CHG;
    if (features & CF_CHG2)
        FeatureMap[1] |= CF_CHG;
    if (features & CF_CHG3)
        FeatureMap[2] |= CF_CHG;
    if (features & CF_CHG4)
        FeatureMap[3] |= CF_CHG;
    if (features & CF_CHG5)
        FeatureMap[4] |= CF_CHG;
    if (features & CF_CHG6)
        FeatureMap[5] |= CF_CHG;

    if (features & CF_USE1)
        FeatureMap[0] |= CF_USE;
    if (features & CF_USE2)
        FeatureMap[1] |= CF_USE;
    if (features & CF_USE3)
        FeatureMap[2] |= CF_USE;
    if (features & CF_USE4)
        FeatureMap[3] |= CF_USE;
    if (features & CF_USE5)
        FeatureMap[4] |= CF_USE;
    if (features & CF_USE6)
        FeatureMap[5] |= CF_USE;

    if (ph.id == PLFM_ARM &&
        (
            insn.itype == ARM_stm && //STMFD SP!,...
            insn.ops[0].type == o_reg &&
            insn.ops[0].reg == 0xd //SP
            )
        )
    {
        FeatureMap[0] |= CF_CHG;
    }
}

char *OpTypeStr[] = {
    "o_void",
    "o_reg",
    "o_mem",
    "o_phrase",
    "o_displ",
    "o_imm",
    "o_far",
    "o_near",
    "o_idpspec0",
    "o_idpspec1",
    "o_idpspec2",
    "o_idpspec3",
    "o_idpspec4",
    "o_idpspec5",
    "o_last" };

int GetInstructionWeight(insn_t instruction)
{
    int Weight = 0;
    Weight = instruction.itype * 1000;
    for (int i = 0; i < UA_MAXOP; i++)
    {
        if (instruction.ops[i].type > 0)
        {
            Weight += instruction.ops[i].type * 100;
            if (instruction.ops[i].type == o_reg)
            {
                Weight += instruction.ops[i].reg;
            }
            else if (instruction.ops[i].type == o_displ)
            {
                Weight += instruction.ops[i].reg;
                Weight += instruction.ops[i].phrase;
            }
            else if (instruction.ops[i].type == o_imm)
            {
                //Weight+=instruction.ops[i].value;
            }
            else if (instruction.ops[i].type == o_near)
            {
                //Weight+=instruction.ops[i].addr;
            }
            else if (instruction.ops[i].type == o_mem)
            {
                //Weight+=instruction.ops[i].addr;
            }
            else if (instruction.ops[i].type == o_phrase)
            {
                Weight += instruction.ops[i].phrase + instruction.ops[i].specflag1;
            }
            else
            {
                /*
                    instruction.ops[i].dtyp,
                    instruction.ops[i].addr,
                    instruction.ops[i].value,
                    instruction.ops[i].specval,
                    ph.regNames[instruction.ops[i].reg],
                    instruction.ops[i].phrase*/
            }
        }
    }
    return Weight;
}

char *EscapeString(qstring& input_string)
{
    //<>{}|
    char *buffer = (char*)malloc(input_string.length() * 2 + 1);
    int j = 0;
    for (int i = 0; i < input_string.length() + 1; i++, j++)
    {
        char ch = input_string[i];
        if (ch == '<' || ch == '>' || ch == '{' || ch == '}' || ch == '|')
        {
            buffer[j] = '\\';
            j++;
            buffer[j] = ch;
        }
        else
        {
            buffer[j] = ch;
        }
    }
    return buffer;
}

void AddInstructionByOrder(map <ea_t, insn_t>& InstructionHash, list <ea_t>& Addresses, ea_t Address)
{
    map <ea_t, insn_t>::iterator InstructionHashIter = InstructionHash.find(Address);

    bool IsInserted = FALSE;
    for (list <ea_t>::iterator AddressesIter = Addresses.begin(); AddressesIter != Addresses.end(); AddressesIter++)
    {
        map <ea_t, insn_t>::iterator CurrentInstructionHashIter = InstructionHash.find(*AddressesIter);
        if (GetInstructionWeight(CurrentInstructionHashIter->second) < GetInstructionWeight(InstructionHashIter->second))
        {
            Addresses.insert(AddressesIter, Address);
            IsInserted = TRUE;
            break;
        }
    }
    if (!IsInserted)
        Addresses.push_back(Address);
}

list <insn_t> *ReoderInstructions(multimap <OperandPosition, OperandPosition, OperandPositionCompareTrait>& InstructionMap, map <ea_t, insn_t>& InstructionHash)
{
    list <insn_t> *CmdArray = new list <insn_t>;
    unordered_set <ea_t> ChildAddresses;
    multimap <OperandPosition, OperandPosition, OperandPositionCompareTrait>::iterator InstructionMapIter;

    for (InstructionMapIter = InstructionMap.begin(); InstructionMapIter != InstructionMap.end(); InstructionMapIter++)
    {
        ChildAddresses.insert(InstructionMapIter->second.Address);
    }

    list <ea_t> RootAddresses;
    map <ea_t, insn_t>::iterator InstructionHashIter;
    for (InstructionHashIter = InstructionHash.begin(); InstructionHashIter != InstructionHash.end(); InstructionHashIter++)
    {
        if (ChildAddresses.find(InstructionHashIter->first) == ChildAddresses.end())
        {
            AddInstructionByOrder(InstructionHash, RootAddresses, InstructionHashIter->first);
        }
    }
    BOOST_LOG_TRIVIAL(debug) << boost::format("InstructionHash=%u, RootAddresses=%u entries", InstructionHash.size(), RootAddresses.size());

    list <ea_t> OrderedAddresses;
    list <string> Signatures;
    for (ea_t address : RootAddresses)
    {
        list <ea_t> TargetAddresses;
        list <ea_t>::iterator TargetAddressesIter;
        TargetAddresses.push_back(address);
        list <insn_t> Signature;
        BOOST_LOG_TRIVIAL(debug) << boost::format("RootAddressesIter=%X ", address);
        for (TargetAddressesIter = TargetAddresses.begin(); TargetAddressesIter != TargetAddresses.end(); TargetAddressesIter++)
        {
            for (int Index = 0; Index < UA_MAXOP; Index++)
            {
                OperandPosition TargetOperandPosition;
                TargetOperandPosition.Address = *TargetAddressesIter;
                TargetOperandPosition.Index = Index;

                list <ea_t> ChildrenAddresses;
                list <ea_t>::iterator ChildrenAddressesIter;

                for (InstructionMapIter = InstructionMap.find(TargetOperandPosition); InstructionMapIter != InstructionMap.end() && InstructionMapIter->first.Address == *TargetAddressesIter && InstructionMapIter->first.Index == Index; InstructionMapIter++)
                {
                    AddInstructionByOrder(InstructionHash, ChildrenAddresses, InstructionMapIter->second.Address);
                }
                for (ChildrenAddressesIter = ChildrenAddresses.begin(); ChildrenAddressesIter != ChildrenAddresses.end(); ChildrenAddressesIter++)
                {
                    TargetAddresses.push_back(*ChildrenAddressesIter);
                }
            }
        }
        //TargetAddresses has all the addresses traversed using BFS
        //Convert it to string and add to string list.
        for (TargetAddressesIter = TargetAddresses.begin(); TargetAddressesIter != TargetAddresses.end(); TargetAddressesIter++)
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format("%X-", *TargetAddressesIter);
            OrderedAddresses.push_back(*TargetAddressesIter);
        }
        //Signatures.push_back();
    }

    //OrderedAddresses
    list <ea_t>::reverse_iterator OrderedAddressesIter;
    for (OrderedAddressesIter = OrderedAddresses.rbegin(); OrderedAddressesIter != OrderedAddresses.rend(); OrderedAddressesIter++)
    {
        list <ea_t>::reverse_iterator TmpAddressesIter = OrderedAddressesIter;
        TmpAddressesIter++;
        for (; TmpAddressesIter != OrderedAddresses.rend(); TmpAddressesIter++)
        {
            if (*TmpAddressesIter == *OrderedAddressesIter)
                *TmpAddressesIter = 0;
        }
    }

    list <ea_t>::iterator AddressesIter;
    for (AddressesIter = OrderedAddresses.begin(); AddressesIter != OrderedAddresses.end(); AddressesIter++)
    {
        InstructionHashIter = InstructionHash.find(*AddressesIter);
        if (InstructionHashIter != InstructionHash.end())
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format("Instruction at %X == %X: ", *AddressesIter, InstructionHashIter->second.ea);
            for (int i = 0; i < UA_MAXOP; i++)
            {
                if (InstructionHashIter->second.ops[i].type > 0)
                {
                    // TODO: Dump InstructionHashIter->second.ops[i];
                }
            }

            CmdArray->push_back(InstructionHashIter->second);
        }
    }
    return CmdArray;
}

enum { CONDITION_FLAG };

list <int> GetRelatedFlags(int itype, bool IsModifying)
{
    list <int> Flags;
    if (IsModifying)
    {
        if (ph.id == PLFM_ARM &&
            (itype == ARM_add ||
                itype == ARM_adc ||
                itype == ARM_sub ||
                itype == ARM_sbc ||
                itype == ARM_rsc ||
                itype == ARM_mul ||
                itype == ARM_mla ||
                itype == ARM_umull ||
                itype == ARM_umlal ||
                itype == ARM_smull ||
                itype == ARM_smlal ||
                itype == ARM_mov ||
                itype == ARM_mvn ||
                itype == ARM_asr ||
                itype == ARM_lsl ||
                itype == ARM_lsr ||
                itype == ARM_ror ||
                //itype == ARM_rrx ||
                itype == ARM_and ||
                itype == ARM_eor ||
                itype == ARM_orr ||
                //itype == ARM_orn ||
                itype == ARM_bic)
            )
        {
            Flags.push_back(CONDITION_FLAG);
        }
    }
    else
    {
        if (ph.id == PLFM_ARM && itype == ARM_b)
        {
            Flags.push_back(CONDITION_FLAG);
        }
    }
    return Flags;
}

///////////////////////////////////////////////////////////
//Save & Trace Variables
void IDAAnalyzer::UpdateInstructionMap
(
    unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn>& OperandsHash,
    unordered_map <int, ea_t>& FlagsHash,
    //Instruction Hash and Map
    multimap <OperandPosition, OperandPosition, OperandPositionCompareTrait>& InstructionMap,
    map <ea_t, insn_t>& InstructionHash,
    insn_t& instruction
)
{
    ea_t address = instruction.ea;
    InstructionHash.insert(pair<ea_t, insn_t>(address, instruction));
    char Features[UA_MAXOP * 2];

    insn_t insn;
    decode_insn(&insn, address);

    GetFeatureBits(instruction.itype, Features, sizeof(Features), insn);

    if (Debug > 0)
        BOOST_LOG_TRIVIAL(debug) << boost::format("%s(%X) %s", ph.instruc[instruction.itype].name, instruction.itype, GetFeatureStr(ph.instruc[instruction.itype].feature).c_str());

    //Flags Tracing
    list <int> Flags = GetRelatedFlags(instruction.itype, true);
    list <int>::iterator FlagsIter;
    for (FlagsIter = Flags.begin(); FlagsIter != Flags.end(); FlagsIter++)
    {
        //Set Flags: FlagsHash
        FlagsHash.insert(pair<int, ea_t>(*FlagsIter, address));
    }

    Flags = GetRelatedFlags(instruction.itype, false);
    for (FlagsIter = Flags.begin(); FlagsIter != Flags.end(); FlagsIter++)
    {
        //Use Flags: FlagsHash
        unordered_map <int, ea_t>::iterator FlagsHashIter = FlagsHash.find(*FlagsIter);
        if (FlagsHashIter != FlagsHash.end())
        {
            //FlagsHashIter->first
            //FlagsHashIter->second
            OperandPosition SrcOperandPosition;
            SrcOperandPosition.Address = FlagsHashIter->second;
            SrcOperandPosition.Index = 0;

            OperandPosition DstOperandPosition;
            DstOperandPosition.Address = address;
            DstOperandPosition.Index = 0;
            InstructionMap.insert(pair<OperandPosition, OperandPosition>(SrcOperandPosition, DstOperandPosition));
        }
    }
    //Return Value Tracing


    //Parameter Tracing
    //ARM_blx/ARM_blx1/ARM_blx2
    if (
        (ph.id == PLFM_ARM && (instruction.itype == ARM_bl || instruction.itype == ARM_blx1 || instruction.itype == ARM_blx2)) ||
        (ph.id == PLFM_MIPS && (instruction.itype == MIPS_jal || instruction.itype == MIPS_jalx))
        )
    {
        op_t operand;
        operand.type = o_reg;
        for (int reg = 0; reg < 5; reg++)
        {
            operand.reg = reg;
            unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn>::iterator iter = OperandsHash.find(operand);
            if (iter != OperandsHash.end())
            {
                OperandPosition SrcOperandPosition;
                SrcOperandPosition.Address = iter->second.Address;
                SrcOperandPosition.Index = iter->second.Index;

                OperandPosition DstOperandPosition;
                DstOperandPosition.Address = address;
                DstOperandPosition.Index = 0;

                InstructionMap.insert(pair<OperandPosition, OperandPosition>(SrcOperandPosition, DstOperandPosition));

            }
            else
            {
                break;
            }
        }
    }

    //Operand Tracing
    for (int i = UA_MAXOP - 1; i >= 0; i--)
    {
        op_t *pOperand = &instruction.ops[i];
        if (pOperand->type > 0)
        {
            //o_mem,o_displ,o_far,o_near -> addr
            //o_reg -> reg
            //o_phrase,o_displ -> phrase
            //outer displacement (o_displ+OF_OUTER_DISP) -> value
            //o_imm -> value
            BOOST_LOG_TRIVIAL(debug) << boost::format("\tOperand %u: [%s%s] ", i, (Features[i] & CF_CHG) ? "CHG" : "", (Features[i] & CF_USE) ? "USE" : "");
            if (Features[i] & CF_USE)
            {
                unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn>::iterator iter = OperandsHash.find(*pOperand);
                if (iter == OperandsHash.end())
                {
                    op_t tmp_op;
                    memset(&tmp_op, 0, sizeof(op_t));
                    tmp_op.type = o_reg;
                    if (pOperand->type == o_displ)
                    {
                        tmp_op.reg = pOperand->reg;
                        iter = OperandsHash.find(tmp_op);
                        if (iter == OperandsHash.end())
                        {
                            tmp_op.reg = pOperand->phrase;
                            iter = OperandsHash.find(tmp_op);
                        }
                    }
                    else if (pOperand->type == o_phrase)
                    {
                        tmp_op.reg = pOperand->specflag1;
                        iter = OperandsHash.find(tmp_op);
                        if (iter == OperandsHash.end())
                        {
                            tmp_op.reg = pOperand->phrase;
                            iter = OperandsHash.find(tmp_op);
                        }
                    }
                }
                if (iter != OperandsHash.end())
                {
                    OperandPosition SrcOperandPosition;
                    SrcOperandPosition.Address = iter->second.Address;
                    SrcOperandPosition.Index = iter->second.Index;

                    OperandPosition DstOperandPosition;
                    DstOperandPosition.Address = address;
                    DstOperandPosition.Index = i;

                    InstructionMap.insert(pair<OperandPosition, OperandPosition>(SrcOperandPosition, DstOperandPosition));
                }
            }

            if (Features[i] & CF_CHG) //Save to hash(addr,i,op_t)
            {
                OperandPosition operand_position;
                operand_position.Address = address;
                operand_position.Index = i;
                OperandsHash.erase(instruction.ops[i]);
                BOOST_LOG_TRIVIAL(debug) << boost::format("Inserting %u", i);
                OperandsHash.insert(pair<op_t, OperandPosition>(instruction.ops[i], operand_position));
            }
        }
    }
}

void IDAAnalyzer::AnalyzeBasicBlock(ea_t srcBlockAddress, list <insn_t> *p_cmdArray, flags_t flags, bool gatherCmdArray)
{
    string disasm_buffer;

    BasicBlock basic_block;
    basic_block.FunctionAddress = 0;
    basic_block.BlockType = UNKNOWN_BLOCK;
    basic_block.StartAddress = srcBlockAddress;
    basic_block.Flag = flags;
    basic_block.EndAddress = 0;

    qstring name;
    get_short_name(&name, srcBlockAddress);

    if (name[0] != NULL)
    {
        basic_block.Name = name.c_str();
    }    

    if (is_code(flags))
    {
        func_t *p_func = get_func(srcBlockAddress);
        if (p_func)
        {
            basic_block.FunctionAddress = p_func->start_ea;
        }

        //BOOST_LOG_TRIVIAL(debug) << boost::format("Function: %X Block : %X (%s)", basic_block.StartAddress, basic_block.FunctionAddress, name);
        //BOOST_LOG_TRIVIAL(debug) << boost::format("Function: %X Block : %X (%s)", basic_block.FunctionAddress, basic_block.StartAddress, name);

        ea_t cref = get_first_cref_to(srcBlockAddress);

        if (cref == BADADDR || basic_block.StartAddress == basic_block.FunctionAddress)
        {
            basic_block.BlockType = FUNCTION_BLOCK;
            if (name[0] == NULL)
            {
                //TODO: Fix - _snprintf(name,sizeof(name)-1,"func_%X",basic_block.StartAddress);
            }
        }
    }

    vector <unsigned char> instructionHash;
    list <insn_t>::iterator cmdArrayIt;
    unsigned char instruction_buffer[0x100];

    for (cmdArrayIt = p_cmdArray->begin(); cmdArrayIt != p_cmdArray->end(); cmdArrayIt++)
    {
        if ((*cmdArrayIt).ea != 0xffffffff && basic_block.EndAddress < ((*cmdArrayIt).ea + (*cmdArrayIt).size))
        {
            basic_block.EndAddress = (*cmdArrayIt).ea + (*cmdArrayIt).size;
        }

        if (is_code(flags) &&
            !(
                //detect hot patching
                basic_block.StartAddress == basic_block.FunctionAddress &&
                cmdArrayIt == p_cmdArray->begin() &&
                (ph.id == PLFM_386 || ph.id == PLFM_IA64) && (*cmdArrayIt).itype == NN_mov && (*cmdArrayIt).ops[0].reg == (*cmdArrayIt).ops[1].reg
                ) &&
            !(
            ((ph.id == PLFM_386 || ph.id == PLFM_IA64) &&
                (
                (*cmdArrayIt).itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
                    (*cmdArrayIt).itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
                    (*cmdArrayIt).itype == NN_jc ||                  // Jump if Carry (CF=1)
                    (*cmdArrayIt).itype == NN_jcxz ||                // Jump if CX is 0
                    (*cmdArrayIt).itype == NN_jecxz ||               // Jump if ECX is 0
                    (*cmdArrayIt).itype == NN_jrcxz ||               // Jump if RCX is 0
                    (*cmdArrayIt).itype == NN_je ||                  // Jump if Equal (ZF=1)
                    (*cmdArrayIt).itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
                    (*cmdArrayIt).itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
                    (*cmdArrayIt).itype == NN_jo ||                  // Jump if Overflow (OF=1)
                    (*cmdArrayIt).itype == NN_jp ||                  // Jump if Parity (PF=1)
                    (*cmdArrayIt).itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
                    (*cmdArrayIt).itype == NN_js ||                  // Jump if Sign (SF=1)
                    (*cmdArrayIt).itype == NN_jz ||                  // Jump if Zero (ZF=1)
                    (*cmdArrayIt).itype == NN_jmp ||                 // Jump
                    (*cmdArrayIt).itype == NN_jmpfi ||               // Indirect Far Jump
                    (*cmdArrayIt).itype == NN_jmpni ||               // Indirect Near Jump
                    (*cmdArrayIt).itype == NN_jmpshort ||            // Jump Short
                    (*cmdArrayIt).itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
                    (*cmdArrayIt).itype == NN_jl ||                  // Jump if Less (SF!=OF)
                    (*cmdArrayIt).itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
                    (*cmdArrayIt).itype == NN_jb ||                  // Jump if Below (CF=1)
                    (*cmdArrayIt).itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
                    (*cmdArrayIt).itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
                    (*cmdArrayIt).itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
                    (*cmdArrayIt).itype == NN_jnb ||                 // Jump if Not Below (CF=0)
                    (*cmdArrayIt).itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
                    (*cmdArrayIt).itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
                    (*cmdArrayIt).itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
                    (*cmdArrayIt).itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
                    (*cmdArrayIt).itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
                    (*cmdArrayIt).itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
                    (*cmdArrayIt).itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
                    (*cmdArrayIt).itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
                    (*cmdArrayIt).itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
                    (*cmdArrayIt).itype == NN_jns ||                 // Jump if Not Sign (SF=0)
                    (*cmdArrayIt).itype == NN_jnz                 // Jump if Not Zero (ZF=0)
                    )
                ) ||
                (
                    ph.id == PLFM_ARM &&
                        (
                            (*cmdArrayIt).itype == ARM_b
                        )
                    )
                )
            )
        {
            instructionHash.push_back((unsigned char)(*cmdArrayIt).itype);
            for (int i = 0; i < UA_MAXOP; i++)
            {
                if ((*cmdArrayIt).ops[i].type != 0)
                {
                    instructionHash.push_back((*cmdArrayIt).ops[i].type);
                    instructionHash.push_back((*cmdArrayIt).ops[i].dtype);
                    /*
                    if((*cmdArrayIt).ops[i].type == o_imm)
                    {
                        InstructionHash.push_back(((*cmdArrayIt).ops[i].value>>24)&0xff);
                        InstructionHash.push_back(((*cmdArrayIt).ops[i].value>>16)&0xff);
                        InstructionHash.push_back(((*cmdArrayIt).ops[i].value>>8)&0xff);
                        InstructionHash.push_back((*cmdArrayIt).ops[i].value&0xff);
                    }*/
                }
            }
        }

        if (is_code(flags))
        {
            qstring buf;

            generate_disasm_line(&buf, (*cmdArrayIt).ea);
            tag_remove(&buf);

            if (Debug > 3)
                BOOST_LOG_TRIVIAL(debug) << boost::format("%X(%X): [%s]", (*cmdArrayIt).ea, basic_block.StartAddress, buf);

            buf += "\n";
            disasm_buffer += buf.c_str();
        }
    }

    /*
    if (gatherCmdArray)
    {
        basic_block.CmdArrayLen = p_cmdArray->size() * sizeof(insn_t);
    }
    else
    {
        basic_block.CmdArrayLen = 0;
    }

    if (gatherCmdArray)
    {
        int CmdArrayIndex = 0;
        for (list <insn_t>::iterator iter = p_cmdArray->begin(); iter != p_cmdArray->end(); iter++, CmdArrayIndex++)
        {
            memcpy(&CmdsPtr[CmdArrayIndex], &(*iter), sizeof(insn_t));
        }
    }
    */

    basic_block.DisasmLines = disasm_buffer;
    basic_block.InstructionHash = BytesToHexString(instructionHash);

    int instructionSize = basic_block.EndAddress - srcBlockAddress;

    unsigned char* instructionBytes = new unsigned char[instructionSize];
    get_bytes((void *) instructionBytes, instructionSize, srcBlockAddress);    
    basic_block.InstructionBytes = BytesToHexString(instructionBytes, instructionSize);
    m_pdisassemblyWriter->AddBasicBlock(basic_block);
}

list <AddressRegion> IDAAnalyzer::GetFunctionBlocks(ea_t address)
{
    ea_t currentAddress;
    size_t current_item_size = 0;
    list <ea_t> blocks;
    list <ea_t>::iterator blocksIter;
    blocks.push_back(address);
    unordered_set <ea_t> AddressHash;
    AddressHash.insert(address);

    list <AddressRegion> regions;

    for (
        blocksIter = blocks.begin();
        blocksIter != blocks.end();
        blocksIter++
        )
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("Analyzing %X", *blocksIter);
        ea_t block_StartAddress = *blocksIter;

        for (currentAddress = block_StartAddress;; currentAddress += current_item_size)
        {
            bool bEndOfBlock = FALSE;

            qstring op_buffer;
            print_insn_mnem(&op_buffer, currentAddress);
            current_item_size = get_item_size(currentAddress);

            if (!strnicmp(op_buffer.c_str(), "ret", 3))
            {
                bEndOfBlock = TRUE;
            }

            insn_t insn;
            decode_insn(&insn, currentAddress);

            ea_t cref = get_first_cref_from(currentAddress);
            while (cref != BADADDR)
            {
                if (
                    insn.itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
                    insn.itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
                    insn.itype == NN_jc ||                  // Jump if Carry (CF=1)
                    insn.itype == NN_jcxz ||                // Jump if CX is 0
                    insn.itype == NN_jecxz ||               // Jump if ECX is 0
                    insn.itype == NN_jrcxz ||               // Jump if RCX is 0
                    insn.itype == NN_je ||                  // Jump if Equal (ZF=1)
                    insn.itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
                    insn.itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
                    insn.itype == NN_jo ||                  // Jump if Overflow (OF=1)
                    insn.itype == NN_jp ||                  // Jump if Parity (PF=1)
                    insn.itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
                    insn.itype == NN_js ||                  // Jump if Sign (SF=1)
                    insn.itype == NN_jz ||                  // Jump if Zero (ZF=1)
                    insn.itype == NN_jmp ||                 // Jump
                    insn.itype == NN_jmpfi ||               // Indirect Far Jump
                    insn.itype == NN_jmpni ||               // Indirect Near Jump
                    insn.itype == NN_jmpshort ||            // Jump Short
                    insn.itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
                    insn.itype == NN_jl ||                  // Jump if Less (SF!=OF)
                    insn.itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
                    insn.itype == NN_jb ||                  // Jump if Below (CF=1)
                    insn.itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
                    insn.itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
                    insn.itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
                    insn.itype == NN_jnb ||                 // Jump if Not Below (CF=0)
                    insn.itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
                    insn.itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
                    insn.itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
                    insn.itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
                    insn.itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
                    insn.itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
                    insn.itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
                    insn.itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
                    insn.itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
                    insn.itype == NN_jns ||                 // Jump if Not Sign (SF=0)
                    insn.itype == NN_jnz                 // Jump if Not Zero (ZF=0)
                    )
                {
                    BOOST_LOG_TRIVIAL(debug) << boost::format("Got Jump at %X", currentAddress);
                    if (AddressHash.find(cref) == AddressHash.end())
                    {
                        BOOST_LOG_TRIVIAL(debug) << boost::format("Adding %X to queue", cref);
                        AddressHash.insert(cref);
                        blocks.push_back(cref);
                    }
                    //cref is the next block position
                    bEndOfBlock = TRUE;
                }
                cref = get_next_cref_from(currentAddress, cref);
            }
            //cref_to
            cref = get_first_cref_to(currentAddress + current_item_size);
            while (cref != BADADDR)
            {
                if (currentAddress != cref)
                {
                    print_insn_mnem(&op_buffer, cref);

                    if (
                        !((ph.id == PLFM_386 || ph.id == PLFM_IA64) && (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)) ||
                        !(ph.id == PLFM_ARM && (insn.itype == ARM_bl || insn.itype == ARM_blx1 || insn.itype == ARM_blx2)) ||
                        !(ph.id == PLFM_MIPS && (insn.itype == MIPS_jal || insn.itype == MIPS_jalx))
                        )
                    {
                        //End of block
                        BOOST_LOG_TRIVIAL(debug) << boost::format("Got End of Block at %X", currentAddress);
                        bEndOfBlock = TRUE;
                    }
                }
                cref = get_next_cref_to(currentAddress + current_item_size, cref);
            }
            if (bEndOfBlock)
            {
                //jump to local block
                //block_StartAddress,currentAddress+item_size is a block
                AddressRegion address_region;
                address_region.startEA = block_StartAddress;
                address_region.endEA = currentAddress + current_item_size;
                regions.push_back(address_region);
                break;
            }
        }
    }

    /*
    list <AddressRegion>::iterator regionsIter;
    for (regionsIter=regions.begin();regionsIter!=regions.end();regionsIter++)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("Collected Addresses %X - %X",(*regionsIter).startEA,(*regionsIter).endEA);
    }
    */
    return regions;
}

ea_t IDAAnalyzer::AnalyzeBlock(ea_t startEA, ea_t endEA, list <insn_t> *p_cmdArray, flags_t *p_flags)
{
    while (1)
    {
        unordered_map <ea_t, ea_t>::iterator newFoundblockIter = m_newBlocks.find(startEA);
        if (newFoundblockIter != m_newBlocks.end())
        {
            BOOST_LOG_TRIVIAL(debug) << boost::format("%s: [newFoundblockIter] Skip %X block to %X", __FUNCTION__, startEA, newFoundblockIter->second);

            if (startEA == newFoundblockIter->second)
                break;

            startEA = newFoundblockIter->second;
        }
        else
        {
            break;
        }
    }

    ea_t currentAddress = startEA;
    ea_t srcBlockAddress = currentAddress;
    ea_t firstBlockEndAddress = 0;
    ea_t currentBlockStartAddress = currentAddress;

    int instructionCount = 0;
    // BOOST_LOG_TRIVIAL(debug) << boost::format("Analyzing %X ~ %X", startEA, endEA);

    bool found_branch = FALSE; //first we branch
    for (; currentAddress <= endEA; )
    {
        instructionCount++;
        bool cref_to_next_addr = FALSE;
        *p_flags = get_full_flags(currentAddress);
        int current_item_size = get_item_size(currentAddress);

        qstring op_buffer;
        print_insn_mnem(&op_buffer, currentAddress);

        insn_t insn;
        decode_insn(&insn, currentAddress);
        p_cmdArray->push_back(insn);
        short current_itype = insn.itype;

        ControlFlow controlFlow;
        //New Location Found
        controlFlow.Src = srcBlockAddress;

        //Finding Next CREF
        vector<ea_t> cref_list;

        //cref from
        ea_t targetAddress = get_first_cref_from(currentAddress);
        while (targetAddress != BADADDR)
        {
            //if just flowing
            if (targetAddress == currentAddress + current_item_size)
            {
                //next instruction...
                cref_to_next_addr = TRUE;
            }
            else
            {
                //j* something or call
                //if branching
                //if cmd type is "call"

                if (
                    (
                    (ph.id == PLFM_386 || ph.id == PLFM_IA64) &&
                        (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)
                        ) ||
                        (
                            ph.id == PLFM_ARM &&
                            (insn.itype == ARM_bl || insn.itype == ARM_blx1 || insn.itype == ARM_blx2)
                            ) ||
                            (ph.id == PLFM_MIPS && (insn.itype == MIPS_jal || insn.itype == MIPS_jalx))
                    )
                {

                    //this is a call
                    //PUSH THIS: call_addrs targetAddress
                    controlFlow.Type = CALL;
                    controlFlow.Dst = targetAddress;

                    m_pdisassemblyWriter->AddControlFlow(controlFlow);
                }
                else {
                    //this is a jump
                    found_branch = TRUE; //j* or ret* instruction found
                    bool IsNOPBlock = FALSE;
                    //check if the jumped position(targetAddress) is a nop block
                    //if insn type is "j*"

                    decode_insn(&insn, targetAddress);

                    if (insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni || insn.itype == NN_jmpshort)
                    {
                        int cref_from_cref_number = 0;
                        ea_t cref_from_cref = get_first_cref_from(targetAddress);
                        while (cref_from_cref != BADADDR)
                        {
                            cref_from_cref_number++;
                            cref_from_cref = get_next_cref_from(targetAddress, cref_from_cref);
                        }
                        if (cref_from_cref_number == 1)
                        {
                            //we add the cref's next position instead cref
                            //because this is a null block(doing nothing but jump)
                            ea_t cref_from_cref = get_first_cref_from(targetAddress);
                            while (cref_from_cref != BADADDR)
                            {
                                //next_ crefs  cref_from_cref
                                cref_list.push_back(cref_from_cref);
                                cref_from_cref = get_next_cref_from(targetAddress, cref_from_cref);
                            }
                            IsNOPBlock = TRUE;
                        }
                    }
                    if (!IsNOPBlock)
                        //all other cases
                    {
                        //PUSH THIS: next_crefs  cref
                        cref_list.push_back(targetAddress);
                    }
                }
            }

            targetAddress = get_next_cref_from(currentAddress, targetAddress);
        }

        if (!found_branch)
        {
            //cref_to
            ea_t cref_to = get_first_cref_to(currentAddress + current_item_size);
            while (cref_to != BADADDR)
            {
                if (cref_to != currentAddress)
                {
                    found_branch = TRUE;
                    break;
                }
                cref_to = get_next_cref_to(currentAddress + current_item_size, cref_to);
            }
            if (!found_branch)
            {
                if (
                    ((ph.id == PLFM_386 || ph.id == PLFM_IA64) && (insn.itype == NN_retn || insn.itype == NN_retf)) ||
                    (ph.id == PLFM_ARM && ((insn.itype == ARM_pop && (insn.ops[0].specval & 0xff00) == 0x8000) || insn.itype == ARM_ret || insn.itype == ARM_bx))
                    )
                {
                    found_branch = TRUE;
                }
                else if (is_code(*p_flags) != is_code(get_full_flags(currentAddress + current_item_size)))
                {
                    //or if code/data type changes
                    found_branch = TRUE; //code, data type change...
                }

                if (!found_branch)
                {
                    if (!is_code(*p_flags) && has_name(*p_flags))
                    {
                        found_branch = TRUE;
                    }
                }
            }
        }

        //Skip Null Block
        if (is_code(*p_flags) &&
            found_branch &&
            cref_to_next_addr)
        {
            ea_t cref = currentAddress + current_item_size;

            insn_t insn;
            decode_insn(&insn, cref);

            if (insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni || insn.itype == NN_jmpshort)
            {
                //we add the cref's next position instead cref
                //because this is a null block(doing nothing but jump)
                ea_t cref_from_cref = get_first_cref_from(cref);
                while (cref_from_cref != BADADDR)
                {
                    //PUSH THIS: next_crefs  cref_from_cref
                    cref_list.push_back(cref_from_cref);
                    cref_from_cref = get_next_cref_from(cref, cref_from_cref);
                }
            }
            else
            {
                //next_crefs  currentAddress+current_item_size
                cref_list.push_back(currentAddress + current_item_size);
            }
        }

        //dref_to
        ea_t dref = get_first_dref_to(currentAddress);
        while (dref != BADADDR)
        {
            //PUSH THIS: dref
            controlFlow.Type = DREF_TO;
            controlFlow.Dst = dref;
            m_pdisassemblyWriter->AddControlFlow(controlFlow);
            dref = get_next_dref_to(currentAddress, dref);
        }

        //dref_from
        dref = get_first_dref_from(currentAddress);
        while (dref != BADADDR)
        {
            //PUSH THIS: next_drefs dref

            controlFlow.Type = DREF_FROM;
            controlFlow.Dst = dref;
            m_pdisassemblyWriter->AddControlFlow(controlFlow);
            dref = get_next_dref_from(currentAddress, dref);
        }

        if (found_branch)
        {
            bool is_positive_jmp = TRUE;
            if (
                current_itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
                current_itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
                current_itype == NN_jc ||                  // Jump if Carry (CF=1)
                current_itype == NN_jcxz ||                // Jump if CX is 0
                current_itype == NN_jecxz ||               // Jump if ECX is 0
                current_itype == NN_jrcxz ||               // Jump if RCX is 0
                current_itype == NN_je ||                  // Jump if Equal (ZF=1)
                current_itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
                current_itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
                current_itype == NN_jo ||                  // Jump if Overflow (OF=1)
                current_itype == NN_jp ||                  // Jump if Parity (PF=1)
                current_itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
                current_itype == NN_js ||                  // Jump if Sign (SF=1)
                current_itype == NN_jz ||                  // Jump if Zero (ZF=1)
                current_itype == NN_jmp ||                 // Jump
                current_itype == NN_jmpfi ||               // Indirect Far Jump
                current_itype == NN_jmpni ||               // Indirect Near Jump
                current_itype == NN_jmpshort ||            // Jump Short
                current_itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
                current_itype == NN_jl ||                  // Jump if Less (SF!=OF)
                current_itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
                current_itype == NN_jb ||                  // Jump if Below (CF=1)
                current_itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
                current_itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
                current_itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
                current_itype == NN_jnb ||                 // Jump if Not Below (CF=0)
                current_itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
                current_itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
                current_itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
                current_itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
                current_itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
                current_itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
                current_itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
                current_itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
                current_itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
                current_itype == NN_jns ||                 // Jump if Not Sign (SF=0)
                current_itype == NN_jnz                 // Jump if Not Zero (ZF=0)
                )
            {
                //map table
                //check last instruction whether it was positive or negative to tweak the map
                if (
                    current_itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
                    current_itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
                    current_itype == NN_jc ||                  // Jump if Carry (CF=1)
                    current_itype == NN_jcxz ||                // Jump if CX is 0
                    current_itype == NN_jecxz ||               // Jump if ECX is 0
                    current_itype == NN_jrcxz ||               // Jump if RCX is 0
                    current_itype == NN_je ||                  // Jump if Equal (ZF=1)
                    current_itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
                    current_itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
                    current_itype == NN_jo ||                  // Jump if Overflow (OF=1)
                    current_itype == NN_jp ||                  // Jump if Parity (PF=1)
                    current_itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
                    current_itype == NN_js ||                  // Jump if Sign (SF=1)
                    current_itype == NN_jz ||                  // Jump if Zero (ZF=1)
                    current_itype == NN_jmp ||                 // Jump
                    current_itype == NN_jmpfi ||               // Indirect Far Jump
                    current_itype == NN_jmpni ||               // Indirect Near Jump
                    current_itype == NN_jmpshort ||            // Jump Short
                    current_itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
                    current_itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
                    current_itype == NN_jnb ||                 // Jump if Not Below (CF=0)
                    current_itype == NN_jnbe                 // Jump if Not Below or Equal (CF=0 & ZF=0)						
                    )
                {
                    is_positive_jmp = TRUE;
                }
                else
                {
                    is_positive_jmp = FALSE;
                }
            }

            vector<ea_t>::iterator cref_list_iter;
            //If Split Block
            //must be jmp,next block has only one cref_to
            if (cref_list.size() == 1 && current_itype == NN_jmp && instructionCount > 1)
            {
                cref_list_iter = cref_list.begin();
                ea_t next_block_addr = *cref_list_iter;

                //cref_to
                int cref_to_count = 0;
                ea_t cref_to = get_first_cref_to(next_block_addr);
                while (cref_to != BADADDR)
                {
                    if (currentAddress != cref_to)
                        cref_to_count++;
                    cref_to = get_next_cref_to(next_block_addr, cref_to);
                }
                if (cref_to_count == 0)
                {
                    //Merge it
                    if (!firstBlockEndAddress)
                        firstBlockEndAddress = currentAddress + current_item_size;
                    //next_block_addr should not be analyzed again next time.
                    if (currentBlockStartAddress != startEA)
                    {
                        BOOST_LOG_TRIVIAL(debug) << boost::format("%s: [newFoundblockIter] Set Analyzed %X~%X", __FUNCTION__, currentBlockStartAddress, currentAddress + current_item_size);
                        m_newBlocks.insert(pair<ea_t, ea_t>(currentBlockStartAddress, currentAddress + current_item_size));
                    }
                    if (currentBlockStartAddress != next_block_addr)
                    {
                        currentBlockStartAddress = next_block_addr;
                        BOOST_LOG_TRIVIAL(debug) << boost::format("%s: [newFoundblockIter] Set currentBlockStartAddress=%X", __FUNCTION__, currentBlockStartAddress);
                        currentAddress = next_block_addr;
                        found_branch = FALSE;
                        cref_list.clear();
                        continue;
                    }
                }
            }
            if (is_positive_jmp)
            {
                for (cref_list_iter = cref_list.begin();
                    cref_list_iter != cref_list.end();
                    cref_list_iter++)
                {
                    controlFlow.Type = CREF_FROM;
                    controlFlow.Dst = *cref_list_iter;
                    m_pdisassemblyWriter->AddControlFlow(controlFlow);
                }
            }
            else
            {
                vector<ea_t>::reverse_iterator cref_list_iter;
                for (cref_list_iter = cref_list.rbegin();
                    cref_list_iter != cref_list.rend();
                    cref_list_iter++)
                {
                    controlFlow.Type = CREF_FROM;
                    controlFlow.Dst = *cref_list_iter;
                    m_pdisassemblyWriter->AddControlFlow(controlFlow);
                }
            }

            if (currentBlockStartAddress != startEA)
            {
                BOOST_LOG_TRIVIAL(debug) << boost::format("%s: [newFoundblockIter] Set Analyzed %X~%X", __FUNCTION__, currentBlockStartAddress, currentAddress + current_item_size);
                m_newBlocks.insert(pair<ea_t, ea_t>(currentBlockStartAddress, currentAddress + current_item_size));
            }

            if (firstBlockEndAddress)
                return firstBlockEndAddress;
            return currentAddress + current_item_size;
        }
        currentAddress += current_item_size;
    }

    if (currentBlockStartAddress != startEA)
    {
        BOOST_LOG_TRIVIAL(debug) << boost::format("%s: [newFoundblockIter] Set Analyzed %X~%X", __FUNCTION__, currentBlockStartAddress, currentAddress);
        m_newBlocks.insert(pair<ea_t, ea_t>(currentBlockStartAddress, currentAddress));
    }

    BOOST_LOG_TRIVIAL(debug) << boost::format("%s: CmdArray size=%u", __FUNCTION__, p_cmdArray->size());
    if (firstBlockEndAddress)
        return firstBlockEndAddress;

    return currentAddress;
}

IDAAnalyzer::IDAAnalyzer(DisassemblyStorage* p_disassemblyStorage)
{
    m_pdisassemblyWriter = p_disassemblyStorage;
}

void IDAAnalyzer::AnalyzeRegion(ea_t startEA, ea_t endEA, bool gatherCmdArray)
{
    BOOST_LOG_TRIVIAL(debug) << boost::format("AnalyzeRegion %X ~ %X", startEA, endEA);

    for (ea_t currentAddressess = startEA; currentAddressess < endEA; )
    {
        list <insn_t> CmdArray;
        flags_t Flag;

        ea_t next_address = AnalyzeBlock(currentAddressess, endEA, &CmdArray, &Flag);
        if (0)
        {
            unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn> OperandsHash;
            multimap <OperandPosition, OperandPosition, OperandPositionCompareTrait> InstructionMap;
            map <ea_t, insn_t> InstructionHash;
            unordered_map <int, ea_t> FlagsHash;

            for (list <insn_t>::iterator cmdArrayIt = CmdArray.begin(); cmdArrayIt != CmdArray.end(); cmdArrayIt++)
            {
                UpdateInstructionMap(OperandsHash, FlagsHash, InstructionMap, InstructionHash, *cmdArrayIt);
            }

            list <insn_t> *NewCmdArray = ReoderInstructions(InstructionMap, InstructionHash);
            if (NewCmdArray)
            {
                AnalyzeBasicBlock(currentAddressess, NewCmdArray, Flag, gatherCmdArray);
                delete NewCmdArray;
            }
        }
        else
        {
            AnalyzeBasicBlock(currentAddressess, &CmdArray, Flag, gatherCmdArray);
        }

        CmdArray.clear();

        if (currentAddressess == next_address)
            break;

        currentAddressess = next_address;
    }
}

void IDAAnalyzer::AnalyzeRegion(AddressRegion& region, bool gatherCmdArray)
{
    AnalyzeRegion(region.startEA, region.endEA, gatherCmdArray);
}

void IDAAnalyzer::Analyze(ea_t startEA, ea_t endEA, bool gatherCmdArray)
{
    BinaryMetaData binaryMetaData;
    memset((char*)&binaryMetaData, 0, sizeof(binaryMetaData));

    BOOST_LOG_TRIVIAL(debug) << boost::format("Retrieving File Information");
    char *input_file_path = NULL;
    get_input_file_path(binaryMetaData.OriginalFilePath, sizeof(binaryMetaData.OriginalFilePath) - 1);

    uchar md5hash[16];
    retrieve_input_file_md5(md5hash);
    binaryMetaData.MD5 = BytesToHexString(md5hash, 16);

    uchar sha256_hash[32];
    retrieve_input_file_sha256(sha256_hash);
    binaryMetaData.SHA256 = BytesToHexString(sha256_hash, 32);
    binaryMetaData.ImageBase = get_imagebase();

    m_pdisassemblyWriter->SetImageBase(binaryMetaData.ImageBase);
    m_pdisassemblyWriter->SetBinaryMetaData(&binaryMetaData);

    BOOST_LOG_TRIVIAL(debug) << boost::format("Analyze: %x ~ %x", startEA, endEA);

    m_pdisassemblyWriter->BeginTransaction();
    if (startEA == 0 && endEA == 0)
    {
        for (int i = 0; i < get_segm_qty(); i++)
        {
            segment_t *seg_p = getnseg(i);
            BOOST_LOG_TRIVIAL(debug) << boost::format("Segment: %d (%llu ~ %llu)", i, seg_p->start_ea, seg_p->end_ea);

            AddressRegion address_region;
            address_region.startEA = seg_p->start_ea;
            address_region.endEA = seg_p->end_ea;
            AnalyzeRegion(address_region, gatherCmdArray);
        }
    }
    else
    {
        //TODO: Porting selected= read_range_selection(&saddr,&eaddr);
        func_t *cur_func_t = get_func(startEA);
        if (cur_func_t->start_ea == startEA)
        {
            //Collect all member addresses
            list <AddressRegion> regions = GetFunctionBlocks(startEA);
            for (list <AddressRegion>::iterator it = regions.begin(); it != regions.end(); it++)
            {
                AnalyzeRegion(*it, gatherCmdArray);
            }
        }
        else
        {
            AddressRegion address_region;
            address_region.startEA = startEA;
            address_region.endEA = endEA;
            AnalyzeRegion(address_region, gatherCmdArray);
        }
    }

    m_pdisassemblyWriter->EndTransaction();
    BOOST_LOG_TRIVIAL(debug) << boost::format("Finished Analysis");
}

bool IDAAnalyzer::IsValidFunctionStart(ea_t address)
{
	int cref_to_count = 0;
	int fcref_to_count = 0;

	ea_t cref = get_first_fcref_to(address);
	while (cref != BADADDR)
	{
		cref_to_count++;

		insn_t insn;
		decode_insn(&insn, cref);

		if (!(insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni))
		{
			return false;
		}
		cref = get_next_fcref_to(address, cref);
	}

	return true;
}

ea_t IDAAnalyzer::GetBlockEnd(ea_t address)
{
	while (address = next_that(address, BADADDR, f_is_code, NULL))
	{
		if (address == BADADDR)
			break;
		ea_t fcref = get_first_fcref_to(address);
		if (fcref != BADADDR)
			break;
	}
	return address;
}

int IDAAnalyzer::ConnectFunctionChunks(ea_t address)
{
	int connected_links_count = 0;
	func_t *func = get_func(address);
	qstring function_name;
	get_short_name(&function_name, address);

	bool is_function = false;
	bool AddFunctionAsMemberOfFunction = false;

	ea_t cref = get_first_cref_to(address);
	while (cref != BADADDR)
	{
		func_t *cref_func = get_func(cref);
		if (cref_func != func)
		{
			insn_t insn;
			decode_insn(&insn, cref);
			if (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)
			{
				is_function = true;
				break;
			}
		}
		cref = get_next_cref_to(address, cref);
	}

	BOOST_LOG_TRIVIAL(debug) << boost::format("ConnectFunctionChunks: %s %s", function_name.c_str(), is_function ? "is function" : "is not function");

	if (!is_function)
	{
		if (func)
			del_func(address);
		cref = get_first_cref_to(address);
		while (cref != BADADDR)
		{
			func_t *cref_func = get_func(cref);
			if (cref_func)
			{
				qstring cref_function_name;
				get_func_name(&cref_function_name, cref);

				BOOST_LOG_TRIVIAL(debug) << boost::format("%s: Adding Location %s(%X) To Function Member Of %s(%X:%X)",
					__FUNCTION__,
					function_name.c_str(),
					address,
					cref_function_name.c_str(),
					cref_func->start_ea,
					cref
				);

				append_func_tail(cref_func, address, GetBlockEnd(address));
				connected_links_count++;
			}
			cref = get_next_cref_to(address, cref);
		}
	}
	else if (AddFunctionAsMemberOfFunction)
	{
		cref = get_first_cref_to(address);
		while (cref != BADADDR)
		{
			insn_t insn;
			decode_insn(&insn, cref);
			if (!(insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni))
			{
				func_t *cref_func = get_func(cref);
				if (cref_func)
				{
					qstring cref_function_name;
					get_func_name(&cref_function_name, cref);
					BOOST_LOG_TRIVIAL(debug) << boost::format("%s: Adding Function %s(%X) To Function Member Of %s(%X:%X)",
						__FUNCTION__,
						function_name, address,
						cref_function_name.c_str(),
						cref_func->start_ea, cref
					);

					append_func_tail(cref_func, address, GetBlockEnd(address));
					connected_links_count++;
				}
			}
			cref = get_next_cref_to(address, cref);
		}
	}
	return connected_links_count;
}

void IDAAnalyzer::FixFunctionChunks()
{
	int connected_links_count = 0;
	do
	{
		connected_links_count = 0;
		for (size_t i = 0; i < get_func_qty(); i++)
		{
			func_t *f = getn_func(i);
			if (!IsValidFunctionStart(f->start_ea))
			{
				qstring function_name;
				get_short_name(&function_name, f->start_ea);

				BOOST_LOG_TRIVIAL(debug) << boost::format("%s: Found invalid function: %s", __FUNCTION__, function_name.c_str());
				connected_links_count += ConnectFunctionChunks(f->start_ea);
			}
		}
	} while (connected_links_count > 0);
}

void IDAAnalyzer::MakeCode(ea_t startAddress, ea_t endAddress)
{
	while (1) {
		bool converted = TRUE;
		BOOST_LOG_TRIVIAL(debug) << boost::format("MakeCode: %X - %X ", startAddress, endAddress);

		del_items(startAddress, 0, endAddress - startAddress);
		for (ea_t addr = startAddress; addr <= endAddress; addr += get_item_size(addr))
		{
			create_insn(addr);
			if (!is_code(get_full_flags(addr)))
			{
				converted = FALSE;
				break;
			}
		}
		if (converted)
			break;
		endAddress += get_item_size(endAddress);
	}
}

ea_t exception_handler_addr = 0L;

void IDAAnalyzer::FixExceptionHandlers()
{
	qstring name;

	for (int n = 0; n < get_segm_qty(); n++)
	{
		segment_t *seg_p = getnseg(n);
		if (seg_p->type == SEG_XTRN)
		{
			asize_t current_item_size;
			ea_t currentAddress;
			for (currentAddress = seg_p->start_ea;
				currentAddress < seg_p->end_ea;
				currentAddress += current_item_size)
			{
				get_name(&name, currentAddress);
				if (!stricmp(name.c_str(), "_except_handler3") || !stricmp(name.c_str(), "__imp__except_handler3"))
				{
					BOOST_LOG_TRIVIAL(debug) << boost::format("name=%s", name);
					//dref_to
					ea_t sub_exception_handler = get_first_dref_to(currentAddress);
					while (sub_exception_handler != BADADDR)
					{
						exception_handler_addr = sub_exception_handler;
						get_name(&name, sub_exception_handler);
						BOOST_LOG_TRIVIAL(debug) << boost::format("name=%s", name.c_str());

						ea_t push_exception_handler = get_first_dref_to(sub_exception_handler);
						while (push_exception_handler != BADADDR)
						{
							BOOST_LOG_TRIVIAL(debug) << boost::format("push exception_handler: %X", push_exception_handler);
							ea_t push_handlers_structure = get_first_cref_to(push_exception_handler);

							while (push_handlers_structure != BADADDR)
							{
								BOOST_LOG_TRIVIAL(debug) << boost::format("push hanlders structure: %X", push_handlers_structure);
								ea_t handlers_structure_start = get_first_dref_from(push_handlers_structure);
								while (handlers_structure_start != BADADDR)
								{
									qstring handlers_structure_start_name;
									get_name(&handlers_structure_start_name, handlers_structure_start);
									ea_t handlers_structure = handlers_structure_start;
									while (1)
									{
										BOOST_LOG_TRIVIAL(debug) << boost::format("handlers_structure: %X", handlers_structure);
										qstring handlers_structure_name;
										get_name(&handlers_structure_name, handlers_structure);

										if ((handlers_structure_name[0] != NULL &&
											strcmp(handlers_structure_start_name.c_str(), handlers_structure_name.c_str())) ||
											is_code(get_full_flags(handlers_structure))
											)
										{
											BOOST_LOG_TRIVIAL(debug) << boost::format("breaking");
											break;
										}
										if ((handlers_structure - handlers_structure_start) % 4 == 0)
										{
											int pos = (handlers_structure - handlers_structure_start) / 4;
											if (pos % 3 == 1 || pos % 3 == 2)
											{
												BOOST_LOG_TRIVIAL(debug) << boost::format("Checking handlers_structure: %X", handlers_structure);

												ea_t exception_handler_routine = get_first_dref_from(handlers_structure);
												while (exception_handler_routine != BADADDR)
												{
													BOOST_LOG_TRIVIAL(debug) << boost::format("Checking exception_handler_routine: %X", exception_handler_routine);
													if (!is_code(get_full_flags(exception_handler_routine)))
													{
														BOOST_LOG_TRIVIAL(debug) << boost::format("Reanalyzing exception_handler_routine: %X", exception_handler_routine);
														ea_t end_pos = exception_handler_routine;
														while (1)
														{
															if (!is_code(get_full_flags(end_pos)))
																end_pos += get_item_size(end_pos);
															else
																break;
														}
														if (!is_code(exception_handler_routine))
														{
															BOOST_LOG_TRIVIAL(debug) << boost::format("routine 01: %X~%X", exception_handler_routine, end_pos);
															MakeCode(exception_handler_routine, end_pos);
														}
													}
													exception_handler_routine = get_next_dref_from(handlers_structure, exception_handler_routine);
												}
											}
										}
										BOOST_LOG_TRIVIAL(debug) << boost::format("checked handlers_structure: %X", handlers_structure);
										handlers_structure += get_item_size(handlers_structure);
									}
									handlers_structure_start = get_next_dref_from(push_handlers_structure, handlers_structure_start);
								}
								push_handlers_structure = get_next_cref_to(push_exception_handler, push_handlers_structure);
							}
							push_exception_handler = get_next_dref_to(sub_exception_handler, push_exception_handler);
						}

						sub_exception_handler = get_next_dref_to(currentAddress, sub_exception_handler);
					}

				}
				current_item_size = get_item_size(currentAddress);
			}
		}
	}
}
