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
import enum
import inspect
import logging
import re
import sys
import threading
import types
from code import InteractiveConsole

from ghidra.framework import Application
from ghidra.pyghidra import PyGhidraScriptProvider, PyGhidraPlugin
from ghidra.pyghidra.interpreter import PyGhidraConsole
from java.io import BufferedReader, InputStreamReader # type:ignore @UnresolvedImport
from java.lang import String # type:ignore @UnresolvedImport 
from java.lang import Thread as JThread # type:ignore @UnresolvedImport
from java.util import Collections # type:ignore @UnresolvedImport
from java.util.function import Consumer # type:ignore @UnresolvedImport
from jpype import JClass, JImplements, JOverride

from pyghidra.internal.plugin.completions import PythonCodeCompleter
from pyghidra.script import PyGhidraScript


logger = logging.getLogger(__name__)


def _run_script(script):
    PyGhidraScript(script).run()


def _current_thread() -> "PyJavaThread":
    return threading.current_thread()


class ThreadState(enum.Enum):
    RUNNING = enum.auto()
    INTERRUPTED = enum.auto()
    KILLED = enum.auto()


def _interpreter_trace(frame: types.FrameType, event: str, _):
    """
    Trace function to be used when the interpreter is executing code.
    This allows it to be interrupted or killed except in native code.
    """
    if event == "line":
        td = _current_thread()
        if td.killed:
            sys.exit()
        if td.interrupted:
            td.clear_interrupted()
            raise KeyboardInterrupt()
    elif event == "call":
        mod = inspect.getmodule(frame.f_code)
        if mod:
            name, _, _ = mod.__name__.partition('.')
            if name in ("_jpype", "jpype"):
                # do not trace these functions to avoid raising during
                # critical python/java bridge functionality
                return None
    return _interpreter_trace


class PyJavaThread(threading.Thread):
    """
    A thread that can be interrupted when running either python or java code
    """
    
    def __init__(self, target=None, name=None, args=(), kwargs=None):
        super().__init__(target=target, name=name, args=args, kwargs=kwargs)
        self._jthread_lock = threading.Lock()
        self._jthread = None
        self._state = ThreadState.RUNNING
        # preload and initialize these exceptions so that their customizers are applied now
        # if a python exception is thrown during customization and it will show an unrelated error
        JClass("java.lang.InterruptedException", initialize=True)
        JClass("java.nio.channels.ClosedByInterruptException", initialize=True)
    
    def run(self):
        try:
            with self._jthread_lock:
                JThread.attachAsDaemon()
                self._jthread = JThread.currentThread()
            super().run()
        finally:
            with self._jthread_lock:
                if self._jthread and JThread.isAttached():
                    self._jthread = None
                    JThread.detach()
    
    def interrupt(self):
        if not self.is_alive():
            return
        with self._jthread_lock:
            if self._jthread:
                self._jthread.interrupt()
        self._state = ThreadState.INTERRUPTED
    
    def clear_interrupted(self):
        self._state = ThreadState.RUNNING

    def kill(self):
        if not self.is_alive():
            return
        with self._jthread_lock:
            if self._jthread:
                self._jthread.interrupt()
        self._state = ThreadState.KILLED
    
    @property
    def interrupted(self) -> bool:
        return self._state == ThreadState.INTERRUPTED
    
    @property
    def killed(self) -> bool:
        return self._state == ThreadState.KILLED


class ConsoleState(enum.Enum):
    DISPOSING = enum.auto()
    IDLE = enum.auto()
    INTERRUPTED = enum.auto()
    RUNNING = enum.auto()
    RESET = enum.auto()


@JImplements(PyGhidraConsole)
class PyConsole(InteractiveConsole):
    """
    PyGhidra Interactive Console
    """
    
    _WORD_PATTERN = re.compile(r".*?([\w\.]+)\Z") # get the last word, including '.', from the right

    def __init__(self, py_plugin: PyGhidraPlugin):
        super().__init__(locals=PyGhidraScript(py_plugin.script))
        appVersion = Application.getApplicationVersion()
        appName = Application.getApplicationReleaseName()
        self.banner = f"Python Interpreter for Ghidra {appVersion} {appName}\n" \
                      f"Python {sys.version} on {sys.platform}"
        console = py_plugin.interpreter.console
        self._console = py_plugin.interpreter.console
        self._line_reader = BufferedReader(InputStreamReader(console.getStdin()))
        self._out = console.getOutWriter()
        self._err = console.getErrWriter()
        self._writer = self._out
        self._thread = None
        self._interact_thread = None
        self._script = self.locals._script
        state = self._script.getState()
        self._script.set(state, self._out)
        self._state = ConsoleState.RESET
        self._completer = PythonCodeCompleter(self)

    def raw_input(self, prompt=''):
        self._console.setPrompt(prompt)
        while True:
            line = self._line_reader.readLine()
            # NOTE: readLine returns None when interrupted
            # but also returns "" when an empty line is entered
            if line is None:
                if self._state in (ConsoleState.DISPOSING, ConsoleState.RESET):
                    sys.exit()
                # if we were not reset, read the next line
                continue
            if not line:
                return '\n'
            return line

    def write(self, data: str):
        if self._state == ConsoleState.INTERRUPTED:
            # don't write the traceback from the KeyboardInterrupt
            return
        self._writer.write(String @ data)
        self._writer.flush()

    @JOverride
    def dispose(self):
        """
        Release the console resources
        """
        self._state = ConsoleState.DISPOSING
        self.close()
        if self._interact_thread:
            # interact thread may be None if the interpreter was never opened
            self._interact_thread.join(timeout=1.0)
            if self._interact_thread.is_alive():
                logger.debug("PyConsole interact_thread failed to join")
            self._interact_thread = None

        # release the console reference since it is held by both Python and Java
        # we are not the owner and are not resposible for disposing it
        self._console = None

    def close(self):
        if self._thread:
            self._thread.kill()

            # closing stdin will wake up any thread attempting to read from it
            # this is required for the join to complete
            self._console.getStdin().close()

            # if we timeout then io out of our control is blocking it
            # at this point we tried and it will complete properly once it stops blocking
            self._thread.join(timeout=1.0)
            if self._thread.is_alive():
                logger.debug("PyConsole execution thread failed to join")

            # ditch the locals so the contents may be released
            self.locals = dict()

    def reset(self):
        self._state = ConsoleState.RESET
        self.close()

        # clear any existing output in the window and re-open the console input
        self._console.clear()

        # this resets the locals, and gets a new code compiler
        super().__init__(locals=PyGhidraScript(self._script))
    
    @property
    def name(self) -> str:
        return "Interpreter"

    @JOverride
    def restart(self):
        self.reset()
        if not self._interact_thread:
            target = self.interact
            kwargs = {"banner": self.banner}
            self._interact_thread = threading.Thread(target=target, name=self.name, kwargs=kwargs)
            self._interact_thread.start()
    
    @JOverride
    def interrupt(self):
        if self._state != ConsoleState.RUNNING:
            # only interrupt the thread if it is actually running code
            return
        if self._thread:
            self._state = ConsoleState.INTERRUPTED
            self._thread.interrupt()
    
    def interact(self, *args, **kwargs):
        while self._state != ConsoleState.DISPOSING:
            # We need a nested thread to handle sys.exit which ends the thread.
            # This is the only way to guarantee the interpreter will never
            # be left in a dead state.
            target = super().interact
            self._thread = PyJavaThread(target=target, name=self.name, args=args, kwargs=kwargs)
            self._state = ConsoleState.IDLE
            self._thread.start()
            self._thread.join()
            if self._state == ConsoleState.IDLE:
                # the user used sys.exit and the thread finished
                # we need to call reset ourselves
                self.reset()

    @contextlib.contextmanager
    def redirect_writer(self):
        self._writer = self._err
        try:
            yield
        finally:
            self._writer = self._out

    def showsyntaxerror(self, filename=None):
        with self.redirect_writer():
            super().showsyntaxerror(filename=filename)

    def showtraceback(self) -> None:
        with self.redirect_writer():
            super().showtraceback()

    @contextlib.contextmanager
    def _run_context(self):
        self._script.start()
        success = False
        try:
            self._state = ConsoleState.RUNNING
            sys.settrace(_interpreter_trace)
            # NOTE: redirect stdout to self so we can flush after each write
            with contextlib.redirect_stdout(self), contextlib.redirect_stderr(self._err):
                yield
                success = True
        except KeyboardInterrupt:
            # not always raised even if actually interrupted
            # catch and use else for consistency
            raise
        else:
            if self._state == ConsoleState.INTERRUPTED:
                raise KeyboardInterrupt()
        finally:
            sys.settrace(None)
            self._state = ConsoleState.IDLE
            self._script.end(success)
            self._out.flush()
            self._err.flush()

    def runcode(self, code):
        with self._run_context():
            super().runcode(code)

    @JOverride
    def getCompletions(self, cmd: str, pos: int):
        try:
            cmd = cmd[:pos]
            match = self._WORD_PATTERN.match(cmd)
            if match:
                cmd = match.group(1)
            return self._completer.get_completions(cmd)
        except Exception:
            return Collections.emptyList()


def _init_plugin(plugin: PyGhidraPlugin):
    console = PyConsole(plugin)
    plugin.interpreter.init(console)       


def setup_plugin():
    PyGhidraPlugin.setInitializer(Consumer @ _init_plugin)
    PyGhidraScriptProvider.setScriptRunner(Consumer @ _run_script)
