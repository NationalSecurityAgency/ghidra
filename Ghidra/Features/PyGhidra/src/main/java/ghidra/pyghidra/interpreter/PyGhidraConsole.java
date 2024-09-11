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

import java.util.List;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.util.Disposable;

/**
 * Console interface providing only the methods which need to be implemented in Python.
 * 
 * This interface is for <b>internal use only</b> and is only public so it can be
 * implemented in Python.
 */
public interface PyGhidraConsole extends Disposable {

    /**
     * Generates code completions for the PyGhidra interpreter
     * 
     * @param cmd The command to get code completions for
     * @param caretPos The position of the caret in the input string 'cmd'.
     *                 It should satisfy the constraint {@literal "0 <= caretPos <= cmd.length()"}
     * @return A {@link List} of {@link CodeCompletion code completions} for the given command
     * @see InterpreterConnection InterpreterConnection.getCompletions(String, int)
     */
    List<CodeCompletion> getCompletions(String cmd, int caretPos);

    /**
     * Restarts the PyGhidra console
     */
    void restart();
    
    /**
     * Interrupts the code running in the PyGhidra console
     */
    void interrupt();
}
