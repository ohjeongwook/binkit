#include <Windows.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/chrono.h>

#include "Function.h"
#include "Structures.h"
#include "Binary.h"
#include "BasicBlocks.h"
#include "DiffAlgorithms.h"

namespace py = pybind11;

PYBIND11_MODULE(pybinkit, m) {
    m.def("load_log_settings", &LoadLogSettings, "Log log settings");

    py::class_<Binary>(m, "Binary")
        .def(py::init<std::string& , int& >(), py::arg("filename"), py::arg("file_id") = 0)
        .def("open", &Binary::Open, "A function to open binary", py::arg("filename"), py::arg("file_id") = 0)
        .def("get_md5", &Binary::GetMD5)
        .def("get_image_base", &Binary::GetImageBase)
        .def("get_basic_blocks", &Binary::GetBasicBlocks, py::return_value_policy::reference)
        .def("get_functions", &Binary::GetFunctions)
        .def("get_function", &Binary::GetFunction, py::return_value_policy::reference)
        .def("get_function_by_start_address", &Binary::GetFunctionByStartAddress, py::return_value_policy::reference);

    /*
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
    */
    py::class_<BasicBlock>(m, "BasicBlock")
        .def(py::init())
        .def_readonly("start_address", &BasicBlock::StartAddress)
        .def_readonly("end_address", &BasicBlock::EndAddress)
        .def_readonly("flag", &BasicBlock::Flag)
        .def_readonly("function_address", &BasicBlock::FunctionAddress)
        .def_readonly("block_type", &BasicBlock::BlockType)
        .def_readonly("name", &BasicBlock::Name)        
        .def_readonly("instruction_hash", &BasicBlock::InstructionHash)
        .def_readonly("instruction_bytes", &BasicBlock::InstructionBytes)
        .def_readonly("disasm_lines", &BasicBlock::DisasmLines);

    py::class_<BasicBlocks>(m, "BasicBlocks")
        .def(py::init())
        .def("get_addresses", &BasicBlocks::GetAddresses)
        .def("get_basic_block", &BasicBlocks::GetBasicBlock)
        .def("get_basic_block_end", &BasicBlocks::GetBasicBlockEnd)        
        .def("get_symbol", &BasicBlocks::GetSymbol)
        .def("get_instruction_hash", &BasicBlocks::GetInstructionHash)
        .def("get_instruction_bytes", &BasicBlocks::GetInstructionBytes)
        .def("get_code_references", &BasicBlocks::GetCodeReferences)
        .def("get_parents", &BasicBlocks::GetParents)
        .def("get_call_targets", &BasicBlocks::GetCallTargets)
        .def("get_disasm_lines", &BasicBlocks::GetDisasmLines);

    py::class_<DiffAlgorithms>(m, "DiffAlgorithms")
        .def(py::init<Binary*, Binary*>())
        .def("do_instruction_hash_match", &DiffAlgorithms::DoInstructionHashMatch)
        .def("do_blocks_instruction_hash_match", &DiffAlgorithms::DoBlocksInstructionHashMatch)
        .def("do_control_flow_match", &DiffAlgorithms::DoControlFlowMatch)
        .def("do_control_flow_matches", &DiffAlgorithms::DoControlFlowMatches)
        .def("get_basic_block_match_combinations", &DiffAlgorithms::GetBasicBlockMatchCombinations);        

    py::class_<Function>(m, "Function")
        .def(py::init())
        .def("get_address", &Function::GetAddress)
        .def("get_basic_blocks", &Function::GetBasicBlocks)
        .def("get_symbol", &Function::GetSymbol);    

    py::class_<AddressPair>(m, "AddressPair")
        .def(py::init<va_t, va_t>())
        .def_readwrite("source", &AddressPair::SourceAddress)
        .def_readwrite("target", &AddressPair::TargetAddress);

    /*
        typedef struct _BasicBlockMatch_ {
            short Type;
            short SubType;
            short Status;
            va_t Addresses[2];
            short MatchRate;
            va_t UnpatchedParentAddress;
            va_t PatchedParentAddress;
        } BasicBlockMatch;
    */
    py::class_<BasicBlockMatch>(m, "BasicBlockMatch")
        .def(py::init())
        .def_readwrite("type", &BasicBlockMatch::Type)
        .def_readwrite("sub_type", &BasicBlockMatch::SubType)
        .def_readwrite("status", &BasicBlockMatch::Status)
        .def_readwrite("source", &BasicBlockMatch::Source)
        .def_readwrite("target", &BasicBlockMatch::Target)
        .def_readwrite("reference_order_difference", &BasicBlockMatch::ReferenceOrderDifference)
        .def_readwrite("match_rate", &BasicBlockMatch::MatchRate)
        .def_readwrite("source_parent", &BasicBlockMatch::SourceParent)
        .def_readwrite("target_parent", &BasicBlockMatch::TargetParent)
        .def_readwrite("match_sequence", &BasicBlockMatch::MatchSequence);

    py::class_<FunctionMatch>(m, "FunctionMatch")
        .def(py::init())
        .def_readwrite("source", &FunctionMatch::SourceFunction)
        .def_readwrite("target", &FunctionMatch::TargetFunction)
        .def_readwrite("matches", &FunctionMatch::BasicBlockMatchList);

    py::class_<FunctionMatching>(m, "FunctionMatching")
        .def(py::init<Binary*, Binary*>())
        .def("do_function_instruction_hash_match", &FunctionMatching::DoFunctionInstructionHashMatch)
        .def("add_matches", &FunctionMatching::AddMatches)
        .def("do_instruction_hash_match", &FunctionMatching::DoInstructionHashMatch)
        .def("do_control_flow_match", &FunctionMatching::DoControlFlowMatch, "Perform control flow matches inside function", py::arg("source_address") = 0, py::arg("matchType") = 1)
        .def("get_matches", &FunctionMatching::GetMatches)
        .def("remove_matches", &FunctionMatching::RemoveMatches);

    py::class_<BasicBlockMatchCombination>(m, "BasicBlockMatchCombination")
        .def(py::init())
        .def("get_match_rate", &BasicBlockMatchCombination::GetMatchRate)
        .def("count", &BasicBlockMatchCombination::Count)
        .def("get", &BasicBlockMatchCombination::Get)
        .def("get_address_pairs", &BasicBlockMatchCombination::GetAddressPairs)        
        .def("get_basic_block_match_list", &BasicBlockMatchCombination::GetBasicBlockMatchList);        
}
