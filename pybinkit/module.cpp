#include <Windows.h>
#include <cmath>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/functional.h>
#include <pybind11/chrono.h>

#include "Binary.h"
#include "DiffAlgorithms.h"

namespace py = pybind11;

PYBIND11_MODULE(pybinkit, m) {
    py::class_<Binary>(m, "Binary")
        .def(py::init())
        .def("open", &Binary::Open)
        .def("get_basic_blocks", &Binary::GetBasicBlocks)
        .def("get_functions", &Binary::GetFunctions);

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
        .def(py::init())
        .def("do_instruction_hash_match", &DiffAlgorithms::DoInstructionHashMatch);
}
