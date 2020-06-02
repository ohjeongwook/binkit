#include <Windows.h>
#include <cmath>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/chrono.h>

#include "Structures.h"
#include "Binary.h"
#include "BasicBlocks.h"
#include "DiffAlgorithms.h"

namespace py = pybind11;

PYBIND11_MODULE(pybinkit, m) {
    py::class_<Binary>(m, "Binary")
        .def(py::init())
        .def("open", &Binary::Open)
        .def("get_basic_blocks", &Binary::GetBasicBlocks, py::return_value_policy::reference)
        .def("get_functions", &Binary::GetFunctions, py::return_value_policy::reference);

    py::class_<BasicBlocks>(m, "BasicBlocks")
        .def(py::init())
        .def("get_addresses", &BasicBlocks::GetAddresses)
        .def("get_symbol", &BasicBlocks::GetSymbol)
        .def("get_instruction_hash", &BasicBlocks::GetInstructionHash)
        .def("get_code_references", &BasicBlocks::GetCodeReferences)
        .def("get_parents", &BasicBlocks::GetParents)
        .def("get_call_targets", &BasicBlocks::GetCallTargets);

    py::class_<Functions>(m, "Functions")
        .def(py::init())
        .def("get_addresses", &Functions::GetAddresses)
        .def("get_basic_blocks", &Functions::GetBasicBlocks);

    py::class_<DiffAlgorithms>(m, "DiffAlgorithms")
        .def(py::init<BasicBlocks&, BasicBlocks&>())
        .def("do_instruction_hash_match", &DiffAlgorithms::DoInstructionHashMatch)
        .def("do_instruction_hash_match_in_blocks", &DiffAlgorithms::DoInstructionHashMatchInBlocks)
        .def("do_control_flow_match", &DiffAlgorithms::DoControlFlowMatch)
        .def("do_control_flow_matches", &DiffAlgorithms::DoControlFlowMatches);

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
        .def_readonly("target_parent", &MatchData::TargetParent);

    py::class_<MatchDataCombination>(m, "MatchDataCombination")
        .def(py::init())
        .def("get_match_rate", &MatchDataCombination::GetMatchRate)
        .def("count", &MatchDataCombination::Count)
        .def("get", &MatchDataCombination::Get)
        .def("get_address_pairs", &MatchDataCombination::GetAddressPairs)        
        .def("get_match_data_list", &MatchDataCombination::GetMatchDataList);        
}
