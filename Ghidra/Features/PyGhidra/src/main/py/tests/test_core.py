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
import textwrap
import importlib
import sys
import jpype
import pyghidra
import pytest

EXE_NAME = "strings.exe"
TEST_LANGUAGE = "JVM:BE:32:default"
TEST_COMPILER = "default"


@pytest.fixture(autouse=True)
def class_file(shared_datadir: Path):
    path = shared_datadir / EXE_NAME
    # creates a java class file of `public class Main {}`
    path.write_bytes(bytes.fromhex("CAFEBABE00000041000A0A000200030700040C000500060100106A6176612F6C616E672F4F626A6563740100063C696E69743E0100032829560700080100044D61696E010004436F6465002100070002000000000001000100050006000100090000001100010001000000052AB70001B1000000000000"))
    yield path


def test_invalid_jpype_keyword_arg():
    assert not jpype.isJVMStarted()

    launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()
    with pytest.raises(TypeError) as ex:
        launcher.start(someBogusKeywordArg=True)
    assert "startJVM() got an unexpected keyword argument 'someBogusKeywordArg'" in str(ex.value)


def test_invalid_vm_arg_succeed():
    assert not jpype.isJVMStarted()

    launcher = pyghidra.launcher.HeadlessPyGhidraLauncher()
    launcher.add_vmargs('-XX:SomeBogusJvmArg')
    launcher.start(ignoreUnrecognized=True)


def test_run_script(capsys, shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    script_path = shared_datadir / "example_script.py"
    pyghidra.run_script(strings_exe, script_path, script_args=["my", "--commands"], analyze=False)
    captured = capsys.readouterr()
    
    assert captured.err == ""

    expected = textwrap.dedent(f"""\
        {script_path} my --commands
        my --commands
        {EXE_NAME} - .ProgramDB
    """)

    assert captured.out == expected


def test_open_program(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pyghidra.open_program(strings_exe, analyze=False, language=TEST_LANGUAGE, compiler=TEST_COMPILER) as flat_api:
        assert flat_api.currentProgram.name == strings_exe.name
        assert flat_api.getCurrentProgram().listing
        assert flat_api.getCurrentProgram().changeable


def test_bad_language(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pytest.raises(ValueError):
        with pyghidra.open_program(
            strings_exe,
            analyze=False,
            language="invalid"
        ) as _:
            pass


def test_bad_compiler(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pytest.raises(ValueError):
        with pyghidra.open_program(
            strings_exe,
            analyze=False,
            language=TEST_LANGUAGE,
            compiler="invalid"
        ) as _:
            pass


def test_no_compiler(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pyghidra.open_program(strings_exe, analyze=False, language=TEST_LANGUAGE) as flat_api:
        pass


def test_no_language_with_compiler(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pyghidra.open_program(strings_exe, analyze=False, compiler=TEST_COMPILER) as flat_api:
        pass


def test_loader(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pyghidra.open_program(
            strings_exe,
            analyze=False,
            language="DATA:LE:64:default",
            compiler="pointer32",
            loader="ghidra.app.util.opinion.BinaryLoader"
        ) as flat_api:
            assert bytes(flat_api.getBytes(flat_api.toAddr(0), 4)) == b"\xCA\xFE\xBA\xBE"


def test_invalid_loader(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pytest.raises(ValueError):
        with pyghidra.open_program(
                strings_exe,
                analyze=False,
                language="DATA:LE:64:default",
                compiler="pointer32",
                loader="notaclass"
            ) as _:
                pass


def test_invalid_loader_type(shared_datadir: Path):
    strings_exe = shared_datadir / EXE_NAME
    with pytest.raises(TypeError):
        with pyghidra.open_program(
                strings_exe,
                analyze=False,
                language="DATA:LE:64:default",
                compiler="pointer32",
                loader="ghidra.app.util.demangler.gnu.GnuDemangler"
            ) as _:
                pass


def test_no_project(capsys, shared_datadir: Path):
    pyghidra.run_script(None, shared_datadir / "projectless_script.py")
    captured = capsys.readouterr()
    assert captured.out.rstrip() == "projectless_script executed successfully"


def test_no_program(capsys, shared_datadir: Path):
    script_path = shared_datadir / "programless_script.py"
    project_path = shared_datadir / "programless_ghidra"

    pyghidra.run_script(None, script_path, project_path, "programless")
    captured = capsys.readouterr()
    assert captured.out.rstrip() == "programless_script executed successfully"


def test_import_script(capsys, shared_datadir: Path):
    script_path = shared_datadir / "import_test_script.py"
    pyghidra.run_script(None, script_path)
    captured = capsys.readouterr()
    assert captured.out.rstrip() == "imported successfully"


def test_import_ghidra_base_java_packages():

    def get_runtime_top_level_java_packages(launcher) -> set:
        from java.lang import Package

        packages = set()

        # Applicaiton needs to fully intialize to find all Ghidra packages
        if launcher.has_launched():

            for package in Package.getPackages():
                # capture base packages only
                packages.add(package.getName().split('.')[0])

        return packages

    def wrap_mod(mod):
        return mod + '_'

    launcher = pyghidra.start()

    # Test to ensure _PyGhidraImportLoader is last loader
    assert isinstance(sys.meta_path[-1], pyghidra.launcher._PyGhidraImportLoader)

    packages = get_runtime_top_level_java_packages(launcher)

    assert len(packages) > 0

    # Test full coverage for Java base packages (_JImportLoader or _PyGhidraImportLoader)
    for mod in packages:
        # check spec using standard import machinery "import mod"
        spec = importlib.util.find_spec(mod)
        if not isinstance(spec.loader, jpype.imports._JImportLoader):
            # handle case with conflict. check spec with "import mod_"
            spec = importlib.util.find_spec(wrap_mod(mod))

        assert spec is not None
        assert isinstance(spec.loader, jpype.imports._JImportLoader) or isinstance(
            spec.loader, pyghidra.launcher._PyGhidraImportLoader)

    # Test all Java base packages are available with '_'
    for mod in packages:
        spec_ = importlib.util.find_spec(wrap_mod(mod))
        assert spec_ is not None
        assert isinstance(spec_.loader, pyghidra.launcher._PyGhidraImportLoader)

    # Test standard import
    import ghidra
    assert isinstance(ghidra.__loader__, jpype.imports._JImportLoader)

    # Test import with conflict
    import pdb_
    assert isinstance(pdb_.__loader__, pyghidra.launcher._PyGhidraImportLoader)

    # Test "from" import with conflict
    from pdb_ import PdbPlugin
    from pdb_.symbolserver import LocalSymbolStore

    # Test _Jpackage handles import that doesn't exist
    try:
        import pdb_.doesntexist
    except ImportError:
        pass
