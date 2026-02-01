/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pyghidra.interpreter;

import java.io.PrintWriter;
import java.util.List;

import javax.swing.Icon;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.pyghidra.PyGhidraPlugin;
import ghidra.util.Disposable;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

/**
 * The PyGhidra interpreter connection
 */
public final class PyGhidraInterpreter implements Disposable, InterpreterConnection {

    private PyGhidraConsole pyghidraConsole = null;
    public final InterpreterConsole console;

    public PyGhidraInterpreter(PyGhidraPlugin plugin, boolean isPythonAvailable) {
        InterpreterPanelService service =
            plugin.getTool().getService(InterpreterPanelService.class);
        console = service.createInterpreterPanel(this, false);
        if (!isPythonAvailable) {
            console.addFirstActivationCallback(this::unavailableCallback);
        }
    }

    @Override
    public void dispose() {
        if (pyghidraConsole != null) {
            pyghidraConsole.dispose();
        }
        console.dispose();
    }

    @Override
    public Icon getIcon() {
        return ResourceManager.loadImage("images/python.png");
    }

    @Override
    public String getTitle() {
        return PyGhidraPlugin.TITLE;
    }

    @Override
    public List<CodeCompletion> getCompletions(String cmd) {
        throw new AssertException("Unreachable, unimplemented and deprecated method");
    }

    @Override
    public List<CodeCompletion> getCompletions(String cmd, int caretPos) {
        if (pyghidraConsole == null) {
            return List.of();
        }
        return pyghidraConsole.getCompletions(cmd, caretPos);
    }

    private void unavailableCallback() {
        console.setInputPermitted(false);
        PrintWriter out = console.getOutWriter();
        out.println("Ghidra was not started with PyGhidra. Python is not available.");
    }

    /**
     * Initializes the interpreter with the provided PyGhidraConsole.
     * 
     * This method is for <b>internal use only</b> and is only public so it can be
     * called from Python.
     * 
     * @param pythonSideConsole the python side console
     * @throws AssertException if the interpreter has already been initialized
     */
    public void init(PyGhidraConsole pythonSideConsole) {
        if (pyghidraConsole != null) {
            throw new AssertException("the interpreter has already been initialized");
        }
        pyghidraConsole = pythonSideConsole;
        console.addFirstActivationCallback(pyghidraConsole::restart);
        console.addAction(new CancelAction(pyghidraConsole));
        console.addAction(new ResetAction(pyghidraConsole));
    }
}
