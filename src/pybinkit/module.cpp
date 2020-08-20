#include <Windows.h>
#include <cmath>
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
    py::class_<Binary>(m, "Binary")
        .def(py::init())
        .def("open", &Binary::Open, "A function to open binary", py::arg("filename"), py::arg("file_id") = 0)
        .def("get_md5", &Binary::GetMD5)
        .def("get_image_base", &Binary::GetImageBase)
        .def("get_basic_blocks", &Binary::GetBasicBlocks, py::return_value_policy::reference)
        .def("get_functions", &Binary::GetFunctions)
        .def("get_function", &Binary::GetFunction, py::return_value_policy::reference);

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
        .def("get_symbol", &BasicBlocks::GetSymbol)
        .def("get_instruction_hash", &BasicBlocks::GetInstructionHash)
        .def("get_instruction_bytes", &BasicBlocks::GetInstructionBytes)
        .def("get_code_references", &BasicBlocks::GetCodeReferences)
        .def("get_parents", &BasicBlocks::GetParents)
        .def("get_call_targets", &BasicBlocks::GetCallTargets)
        .def("get_disasm_lines", &BasicBlocks::GetDisasmLines);

    py::class_<DiffAlgorithms>(m, "DiffAlgorithms")
        .def(py::init<Binary&, Binary&>())
        .def("do_instruction_hash_match", &DiffAlgorithms::DoInstructionHashMatch)
        .def("do_blocks_instruction_hash_match", &DiffAlgorithms::DoBlocksInstructionHashMatch)
        .def("do_function_instruction_hash_match", &DiffAlgorithms::DoFunctionInstructionHashMatch)
        .def("do_control_flow_match", &DiffAlgorithms::DoControlFlowMatch)
        .def("do_control_flow_matches", &DiffAlgorithms::DoControlFlowMatches)
        .def("get_match_data_combinations", &DiffAlgorithms::GetMatchDataCombinations);        

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
        typedef struct _MatchData_ {
            short Type;
            short SubType;
            short Status;
            va_t Addresses[2];
            short MatchRate;
            va_t UnpatchedParentAddress;
            va_t PatchedParentAddress;
        } MatchData;
    */
    py::class_<MatchData>(m, "MatchData")
        .def(py::init())
        .def_readonly("type", &MatchData::Type)
        .def_readonly("sub_type", &MatchData::SubType)
        .def_readonly("status", &MatchData::Status)
        .def_readonly("source", &MatchData::Source)
        .def_readonly("target", &MatchData::Target)
        .def_readonly("reference_order_difference", &MatchData::ReferenceOrderDifference)        
        .def_readonly("match_rate", &MatchData::MatchRate)
        .def_readonly("source_parent", &MatchData::SourceParent)
        .def_readonly("target_parent", &MatchData::TargetParent)
        .def_readonly("match_sequence", &MatchData::MatchSequence);

    py::class_<FunctionMatch>(m, "FunctionMatch")
        .def(py::init())
        .def_readonly("source", &FunctionMatch::SourceFunction)
        .def_readonly("target", &FunctionMatch::TargetFunction)
        .def_readonly("match_data_list", &FunctionMatch::MatchDataList);

    py::class_<FunctionMatches>(m, "FunctionMatches")
        .def(py::init<Binary&, Binary&>())
        .def("add_matches", &FunctionMatches::AddMatches)
        .def("get_matches", &FunctionMatches::GetMatches)
        .def("do_instruction_hash_match", &FunctionMatches::DoInstructionHashMatch)
        .def("do_control_flow_match", &FunctionMatches::DoControlFlowMatch, "Perform control flow matches inside function", py::arg("source_address") = 0)
        .def("remove_matches", &FunctionMatches::RemoveMatches);

    py::class_<MatchDataCombination>(m, "MatchDataCombination")
        .def(py::init())
        .def("get_match_rate", &MatchDataCombination::GetMatchRate)
        .def("count", &MatchDataCombination::Count)
        .def("get", &MatchDataCombination::Get)
        .def("get_address_pairs", &MatchDataCombination::GetAddressPairs)        
        .def("get_match_data_list", &MatchDataCombination::GetMatchDataList);        
}
