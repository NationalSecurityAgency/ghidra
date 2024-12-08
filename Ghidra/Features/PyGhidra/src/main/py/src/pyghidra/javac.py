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
import logging
import shutil
import tempfile
from pathlib import Path
from os import pathsep
from typing import List

from jpype import JImplements, JOverride

logger = logging.getLogger(__name__)


COMPILER_OPTIONS = ["-target", "21", "-source", "21"]


def _to_jar_(jar_path: Path, root: Path):
    from java.io import ByteArrayOutputStream # type:ignore @UnresolvedImport
    from java.util.jar import JarEntry, JarOutputStream # type:ignore @UnresolvedImport

    out = ByteArrayOutputStream()
    with JarOutputStream(out) as jar:
        for p in root.glob("**/*.class"):
            p = p.resolve()
            jar.putNextEntry(JarEntry(str(p.relative_to(root).as_posix())))
            jar.write(p.read_bytes())
            jar.closeEntry()
    jar_path.write_bytes(out.toByteArray())


@JImplements("javax.tools.DiagnosticListener", deferred=True)
class _CompilerDiagnosticListener:

    def __init__(self):
        from javax.tools import Diagnostic # type:ignore @UnresolvedImport
        self.errors: List[Diagnostic] = []

    @JOverride
    def report(self, diagnostic):
        from javax.tools import Diagnostic # type:ignore @UnresolvedImport
        diagnostic: Diagnostic = diagnostic

        kind = diagnostic.getKind()

        if kind == Diagnostic.Kind.ERROR:
            self.errors.append(diagnostic)
        elif kind == Diagnostic.Kind.WARNING:
            logger.info(str(kind))


def java_compile(src_path: Path, jar_path: Path):
    """
    Compiles the provided Java source

    :param src_path: The path to the java file or the root directory of the java source files
    :param jar_path: The path to write the output jar to
    :raises ValueError: If an error occurs when compiling the Java source
    """

    from java.lang import System # type:ignore @UnresolvedImport
    from java.io import Writer # type:ignore @UnresolvedImport
    from java.nio.file import Path as JPath # type:ignore @UnresolvedImport
    from javax.tools import StandardLocation, ToolProvider # type:ignore @UnresolvedImport

    with tempfile.TemporaryDirectory() as out:
        outdir = Path(out).resolve()
        compiler = ToolProvider.getSystemJavaCompiler()
        fman = compiler.getStandardFileManager(None, None, None)
        cp = [JPath @ (Path(p)) for p in System.getProperty("java.class.path").split(pathsep)]
        fman.setLocationFromPaths(StandardLocation.CLASS_PATH, cp)
        if src_path.is_dir():
            fman.setLocationFromPaths(StandardLocation.SOURCE_PATH, [JPath @ (src_path.resolve())])
        fman.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, [JPath @ (outdir)])
        sources = None
        if src_path.is_file():
            sources = fman.getJavaFileObjectsFromPaths([JPath @ (src_path)])
        else:
            glob = src_path.glob("**/*.java")
            sources = fman.getJavaFileObjectsFromPaths([JPath @ (p) for p in glob])

        diagnostics = _CompilerDiagnosticListener()
        task = compiler.getTask(Writer.nullWriter(), fman, diagnostics, COMPILER_OPTIONS, None, sources)

        if not task.call():
            msg = "\n".join([str(error) for error in diagnostics.errors])
            raise ValueError(msg)

        if jar_path.suffix == '.jar':
            jar_path.parent.mkdir(exist_ok=True, parents=True)
            _to_jar_(jar_path, outdir)
        else:
            shutil.copytree(outdir, jar_path, dirs_exist_ok=True)
