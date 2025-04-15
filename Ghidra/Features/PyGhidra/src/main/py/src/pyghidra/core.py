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
import contextlib
from typing import Union, TYPE_CHECKING, Tuple, ContextManager, List, Optional

from pyghidra.converters import *  # pylint: disable=wildcard-import, unused-wildcard-import


if TYPE_CHECKING:
    from pyghidra.launcher import PyGhidraLauncher
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.lang import CompilerSpec, Language, LanguageService
    from ghidra.program.model.listing import Program


def start(verbose=False, *, install_dir: Path = None) -> "PyGhidraLauncher":
    """
    Starts the JVM and fully initializes Ghidra in Headless mode.

    :param verbose: Enable verbose output during JVM startup (Defaults to False)
    :param install_dir: The path to the Ghidra installation directory.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable)
    :return: The PyGhidraLauncher used to start the JVM
    """
    from pyghidra.launcher import HeadlessPyGhidraLauncher
    launcher = HeadlessPyGhidraLauncher(verbose=verbose,  install_dir=install_dir)
    launcher.start()
    return launcher


def started() -> bool:
    """
    Whether the PyGhidraLauncher has already started.
    """
    from pyghidra.launcher import PyGhidraLauncher
    return PyGhidraLauncher.has_launched()


def _get_language(lang_id: str) -> "Language":
    from ghidra.program.util import DefaultLanguageService
    from ghidra.program.model.lang import LanguageID, LanguageNotFoundException
    try:
        service: "LanguageService" = DefaultLanguageService.getLanguageService()
        return service.getLanguage(LanguageID(lang_id))
    except LanguageNotFoundException:
        # suppress the java exception
        pass
    raise ValueError("Invalid Language ID: " + lang_id)


def _get_compiler_spec(lang: "Language", compiler: str = None) -> "CompilerSpec":
    if compiler is None:
        return lang.getDefaultCompilerSpec()
    from ghidra.program.model.lang import CompilerSpecID, CompilerSpecNotFoundException
    try:
        return lang.getCompilerSpecByID(CompilerSpecID(compiler))
    except CompilerSpecNotFoundException:
        # suppress the java exception
        pass
    lang_id = lang.getLanguageID()
    raise ValueError(f"Invalid CompilerSpecID: {compiler} for Language: {lang_id.toString()}")


def _setup_project(
        binary_path: Union[str, Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        language: str = None,
        compiler: str = None,
        loader: Union[str, JClass] = None,
        program_name: str = None
) -> Tuple["GhidraProject", "Program"]:
    from ghidra.base.project import GhidraProject
    from java.lang import ClassLoader  # type:ignore @UnresolvedImport
    from ghidra.framework.model import ProjectLocator # type:ignore @UnresolvedImport
    if binary_path is not None:
        binary_path = Path(binary_path)
    if program_name is None and binary_path is not None:
        program_name = binary_path.name
    if project_location:
        project_location = Path(project_location)
    else:
        project_location = binary_path.parent
    if not project_name:
        project_name = f"{binary_path.name}_ghidra"
    project_location /= project_name

    if isinstance(loader, str):
        from java.lang import ClassNotFoundException # type:ignore @UnresolvedImport
        try:
            gcl = ClassLoader.getSystemClassLoader()
            loader = JClass(loader, gcl)
        except (TypeError, ClassNotFoundException) as e:
            raise ValueError from e

    if isinstance(loader, JClass):
        from ghidra.app.util.opinion import Loader
        loader_cls = Loader.class_
        if not loader_cls.isAssignableFrom(loader):
            raise TypeError(f"{loader} does not implement ghidra.app.util.opinion.Loader")

    # Open/Create project
    program: "Program" = None
    if ProjectLocator(project_location, project_name).exists():
        project = GhidraProject.openProject(project_location, project_name, True)
    else:
        project_location.mkdir(exist_ok=True, parents=True)
        project = GhidraProject.createProject(project_location, project_name, False)      
    if program_name is not None:
        if project.getRootFolder().getFile(program_name):
            program = project.openProgram("/", program_name, False)

    # NOTE: GhidraProject.importProgram behaves differently when a loader is provided
    # loaderClass may not be null so we must use the correct method override

    if binary_path is not None and program is None:
        if language is None:
            if loader is None:
                program = project.importProgram(binary_path)
            else:
                program = project.importProgram(binary_path, loader)
            if program is None:
                raise RuntimeError(f"Ghidra failed to import '{binary_path}'. Try providing a language manually.")
        else:
            lang = _get_language(language)
            comp = _get_compiler_spec(lang, compiler)
            if loader is None:
                program = project.importProgram(binary_path, lang, comp)
            else:
                program = project.importProgram(binary_path, loader, lang, comp)
            if program is None:
                message = f"Ghidra failed to import '{binary_path}'. "
                if compiler:
                    message += f"The provided language/compiler pair ({language} / {compiler}) may be invalid."
                else:
                    message += f"The provided language ({language}) may be invalid."
                raise ValueError(message)
        project.saveAs(program, "/", program_name, True)

    return project, program


def _setup_script(project: "GhidraProject", program: "Program"):
    from pyghidra.script import PyGhidraScript
    from ghidra.app.script import GhidraState
    from ghidra.program.util import ProgramLocation
    from ghidra.util.task import TaskMonitor

    from java.io import PrintWriter # type:ignore @UnresolvedImport
    from java.lang import System # type:ignore @UnresolvedImport

    if project is not None:
        project = project.getProject()

    location = None
    if program is not None:
        # create a GhidraState and setup a HeadlessScript with it
        mem = program.getMemory().getLoadedAndInitializedAddressSet()
        if not mem.isEmpty():
            location = ProgramLocation(program, mem.getMinAddress())
    state = GhidraState(None, project, program, location, None, None)
    script = PyGhidraScript()
    script.set(state, TaskMonitor.DUMMY, PrintWriter(System.out))
    return script


def _analyze_program(flat_api, program):
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil
    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            flat_api.analyzeAll(program)
            if hasattr(GhidraProgramUtilities, "markProgramAnalyzed"):
                GhidraProgramUtilities.markProgramAnalyzed(program)
            else:
                GhidraProgramUtilities.setAnalyzedFlag(program, True)  # @UndefinedVariable
        finally:
            GhidraScriptUtil.releaseBundleHostReference()


@contextlib.contextmanager
def open_program(
        binary_path: Union[str, Path],
        project_location: Union[str, Path] = None,
        project_name: str = None,
        analyze=True,
        language: str = None,
        compiler: str = None,
        loader: Union[str, JClass] = None,
        program_name: str = None
) -> ContextManager["FlatProgramAPI"]: # type: ignore
    """
    Opens given binary path (or optional program name) in Ghidra and returns FlatProgramAPI object.

    :param binary_path: Path to binary file, may be None.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param analyze: Whether to run analysis before returning.
    :param language: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :param loader: The `ghidra.app.util.opinion.Loader` class to use when importing the program.
        This may be either a Java class or its path. (Defaults to None)
    :param program_name: The name of the program to open in Ghidra.
        (Defaults to None, which results in the name being derived from "binary_path")
    :return: A Ghidra FlatProgramAPI object.
    :raises ValueError: If the provided language, compiler or loader is invalid.
    :raises TypeError: If the provided loader does not implement `ghidra.app.util.opinion.Loader`.
    """

    from pyghidra.launcher import PyGhidraLauncher, HeadlessPyGhidraLauncher

    if not PyGhidraLauncher.has_launched():
        HeadlessPyGhidraLauncher().start()

    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.flatapi import FlatProgramAPI

    project, program = _setup_project(
        binary_path,
        project_location,
        project_name,
        language,
        compiler,
        loader,
        program_name
    )
    GhidraScriptUtil.acquireBundleHostReference()

    try:
        flat_api = FlatProgramAPI(program)

        if analyze:
            _analyze_program(flat_api, program)

        yield flat_api
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        project.save(program)
        project.close()


@contextlib.contextmanager
def _flat_api(
        binary_path: Union[str, Path] = None,
        project_location: Union[str, Path] = None,
        project_name: str = None,
        verbose=False,
        analyze=True,
        language: str = None,
        compiler: str = None,
        loader: Union[str, JClass] = None,
        *,
        install_dir: Path = None
):
    """
    Runs a given script on a given binary path.

    :param binary_path: Path to binary file, may be None.
    :param script_path: Path to script to run.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra")
    :param script_args: Command line arguments to pass to script.
    :param verbose: Enable verbose output during Ghidra initialization.
    :param analyze: Whether to run analysis, if a binary_path is provided, before returning.
    :param language: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :param loader: The `ghidra.app.util.opinion.Loader` class to use when importing the program.
        This may be either a Java class or its path. (Defaults to None)
    :param install_dir: The path to the Ghidra installation directory. This parameter is only
        used if Ghidra has not been started yet.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable)
    :raises ValueError: If the provided language, compiler or loader is invalid.
    :raises TypeError: If the provided loader does not implement `ghidra.app.util.opinion.Loader`.
    """
    from pyghidra.launcher import PyGhidraLauncher, HeadlessPyGhidraLauncher

    if not PyGhidraLauncher.has_launched():
        HeadlessPyGhidraLauncher(verbose=verbose, install_dir=install_dir).start()

    project, program = None, None
    if binary_path or project_location:
        project, program = _setup_project(
            binary_path,
            project_location,
            project_name,
            language,
            compiler,
            loader
        )

    from ghidra.app.script import GhidraScriptUtil

    # always aquire a bundle reference to avoid a NPE when attempting to run any Java scripts
    GhidraScriptUtil.acquireBundleHostReference()
    try:
        script = _setup_script(project, program)
        if analyze and program is not None:
            _analyze_program(script, program)
        yield script
    finally:
        GhidraScriptUtil.releaseBundleHostReference()
        if project is not None:
            if program is not None:
                project.save(program)
            project.close()


# pylint: disable=too-many-arguments
def run_script(
    binary_path: Optional[Union[str, Path]],
    script_path: Union[str, Path],
    project_location: Union[str, Path] = None,
    project_name: str = None,
    script_args: List[str] = None,
    verbose=False,
    analyze=True,
    lang: str = None,
    compiler: str = None,
    loader: Union[str, JClass] = None,
    *,
    install_dir: Path = None
):
    """
    Runs a given script on a given binary path.

    :param binary_path: Path to binary file, may be None.
    :param script_path: Path to script to run.
    :param project_location: Location of Ghidra project to open/create.
        (Defaults to same directory as binary file if None)
    :param project_name: Name of Ghidra project to open/create.
        (Defaults to name of binary file suffixed with "_ghidra" if None)
    :param script_args: Command line arguments to pass to script.
    :param verbose: Enable verbose output during Ghidra initialization.
    :param analyze: Whether to run analysis, if a binary_path is provided, before running the script.
    :param lang: The LanguageID to use for the program.
        (Defaults to Ghidra's detected LanguageID)
    :param compiler: The CompilerSpecID to use for the program. Requires a provided language.
        (Defaults to the Language's default compiler)
    :param loader: The `ghidra.app.util.opinion.Loader` class to use when importing the program.
        This may be either a Java class or its path. (Defaults to None)
    :param install_dir: The path to the Ghidra installation directory. This parameter is only
        used if Ghidra has not been started yet.
        (Defaults to the GHIDRA_INSTALL_DIR environment variable)
    :raises ValueError: If the provided language, compiler or loader is invalid.
    :raises TypeError: If the provided loader does not implement `ghidra.app.util.opinion.Loader`.
    """
    script_path = str(script_path)
    args = binary_path, project_location, project_name, verbose, analyze, lang, compiler, loader
    with _flat_api(*args, install_dir=install_dir) as script:
        script.run(script_path, script_args)
