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
        .def("get_function_basic_blocks", &Functions::GetFunctionBasicBlocks);

    py::class_<DiffAlgorithms>(m, "DiffAlgorithms")
        .def(py::init<BasicBlocks&, BasicBlocks&>())
        .def("do_instruction_hash_match", &DiffAlgorithms::DoInstructionHashMatch)
        .def("do_control_flow_match", &DiffAlgorithms::DoControlFlowMatch)
        .def("do_control_flow_matches", &DiffAlgorithms::DoControlFlowMatches);
    

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
        .def_readwrite("type", &MatchData::Type)
        .def_readwrite("sub_type", &MatchData::SubType)
        .def_readwrite("status", &MatchData::Status)
        .def_readonly("source", &MatchData::Source)
        .def_readonly("target", &MatchData::Target)
        .def_readwrite("match_rate", &MatchData::MatchRate)
        .def_readwrite("source_parent", &MatchData::SourceParent)
        .def_readwrite("target_parent", &MatchData::TargetParent);
}
