## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
from pathlib import Path
from typing import List, Tuple

import pytest
from pyghidra.__main__ import _get_parser, PyGhidraArgs
from pyghidra.ghidra_launch import ParsedArgs
from pyghidra.ghidra_launch import get_parser as get_ghidra_launcher_parser


PROJECT_NAME = "stub_name"
EXE_NAME = "strings.exe"


@pytest.fixture(autouse=True)
def exe_file(shared_datadir: Path):
    path = shared_datadir / EXE_NAME
    path.touch()
    yield path


class TestArgParser:

    def parse(self, *args) -> PyGhidraArgs:
        parser = _get_parser()
        parser_args = PyGhidraArgs(parser)
        args = [str(arg) for arg in args]
        parser.parse_args(args, namespace=parser_args)
        return parser_args

    @pytest.fixture(autouse=True)
    def _test_root(self, shared_datadir: Path):
        self.test_root = shared_datadir

    @property
    def example_script(self) -> Path:
        return self.test_root / "example_script.py"

    @property
    def example_exe(self) -> Path:
        return self.test_root / EXE_NAME

    @property
    def ghost_script(self) -> Path:
        return self.test_root / "ghost_script.py"

    @property
    def ghost_exe(self) -> Path:
        return self.test_root / "ghost.exe"

    def test_no_args(self):
        args = self.parse()
        assert args.valid

    def test_verbose_flag(self):
        args = self.parse("-v")
        assert args.verbose is True

    def test_project_name(self):
        args = self.parse("--project-name", PROJECT_NAME)
        assert args.project_name == PROJECT_NAME
        assert args.binary_path is None
        assert args.script_path is None
        assert args.project_path is None

    def test_project_path(self):
        args = self.parse("--project-path", self.test_root)
        assert args.valid
        assert args.project_path == self.test_root
        assert args.binary_path is None
        assert args.script_path is None
        assert args.project_name is None

    def test_script(self):
        args = self.parse(self.example_script)
        assert args.valid
        assert args.script_path == self.example_script

    def test_non_existing_script(self):
        args = self.parse(self.ghost_script)
        assert args.valid is False
        assert args.script_path == self.ghost_script
        assert args.binary_path is None

    def test_binary(self):
        args = self.parse(self.example_exe)
        assert args.valid
        assert args.binary_path == self.example_exe

    def test_non_existing_binary(self):
        args = self.parse(self.ghost_exe)
        assert args.valid is False
        assert args.binary_path == self.ghost_exe

    def test_non_existing_binary_plus_script(self):
        args = self.parse(self.ghost_exe, self.example_script)
        assert args.valid is False
        assert args.binary_path == self.ghost_exe
        assert args.script_path == self.example_script

    def test_script_with_non_existing_binary_arg(self):
        args = self.parse(self.example_script, self.ghost_exe)
        assert args.valid
        assert args.binary_path is None
        assert args.script_path == self.example_script
        assert args.script_args == [str(self.ghost_exe)]

    def test_script_with_optional_args(self):
        args = self.parse(self.example_script, "--project-path", "-v", self.test_root)
        assert args.valid
        assert args.verbose is False
        assert args.script_path == self.example_script
        assert args.script_args == ["--project-path", "-v", str(self.test_root)]

    def test_script_with_positional_args(self):
        args = self.parse(
            self.example_script,
            self.test_root,
            self.example_script,
            self.ghost_script
        )
        assert args.valid
        assert args.verbose is False
        assert args.binary_path is None
        assert args.script_path == self.example_script
        script_args = [
            str(arg) for arg in (self.test_root, self.example_script, self.ghost_script)
        ]
        assert args.script_args == script_args

    def test_script_with_intermingled_args(self):
        args = self.parse(
            self.example_script,
            self.example_exe,
            "-v",
            self.test_root,
            "--project-path",
            self.ghost_exe
        )
        assert args.valid
        assert args.verbose is False
        assert args.script_path == self.example_script
        script_args = [
            str(self.example_exe),
            "-v", str(self.test_root),
            "--project-path",
            str(self.ghost_exe)
        ]
        assert args.script_args == script_args

    def test_binary_script_with_intermingled_args(self):
        args = self.parse(
            "--project-name",
            PROJECT_NAME,
            self.example_exe,
            self.example_script,
            self.ghost_exe,
            "-v",
            self.test_root,
            "--project-name",
            self.ghost_exe
        )
        assert args.valid
        assert args.verbose is False
        assert args.project_name == PROJECT_NAME
        assert args.binary_path == self.example_exe
        assert args.script_path == self.example_script
        script_args = [
            str(self.ghost_exe),
            "-v",
            str(self.test_root),
            "--project-name",
            str(self.ghost_exe)
        ]
        assert args.script_args == script_args

    def test_skip_analysis(self):
        args = self.parse(
            "--skip-analysis"
        )
        assert args.skip_analysis

    def test_default_analysis(self):
        args = self.parse()
        assert not args.skip_analysis

    def test_jvm_args(self):
        ARG1 = "-Duser.variant="
        ARG2 = "-Xmx1M"
        args = self.parse(ARG1, ARG2)
        jvm_args = args.jvm_args
        assert jvm_args
        assert ARG1 in jvm_args
        assert ARG2 in jvm_args


class TestGhidraLaunchParser:

    def parse(self, *args) -> Tuple[ParsedArgs, str]:
        parser = get_ghidra_launcher_parser()

        parser_args = ParsedArgs()
        _, remaining = parser.parse_known_args(args, namespace=parser_args)
        return parser_args, remaining
    
    def test_class_name(self):
        CLASS_ARG = "ghidra.GhidraRun"
        args, _ = self.parse("-g", CLASS_ARG, "arg1", "arg2", "--arg3", "value3")
        assert args.class_name == CLASS_ARG
    
    def test_gui_mode(self):
        args, _ = self.parse("ghidra.GhidraRun", "arg1", "-g", "arg2", "--arg3", "value3")
        assert args.gui
    
    def test_jvm_args(self):
        JVM_ARG1 = "-Duser.variant="
        JVM_ARG2 = "-Xmx1M"
        args, _ = self.parse("ghidra.GhidraRun", "arg1", JVM_ARG1, "arg2", "--arg3", "value3", JVM_ARG2)
        jvm_args = args.jvm_args
        assert jvm_args
        assert JVM_ARG1 in jvm_args
        assert JVM_ARG2 in jvm_args
    
    def test_remaining(self):
        _, remaining = self.parse("ghidra.GhidraRun", "arg1", "-Duser.variant=", "arg2", "--arg3", "value3", "-Xmx1M")
        assert remaining
        assert remaining == ["arg1", "arg2", "--arg3", "value3"]
