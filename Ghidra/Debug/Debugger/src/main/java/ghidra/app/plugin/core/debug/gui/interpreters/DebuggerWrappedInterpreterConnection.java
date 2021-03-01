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
package ghidra.app.plugin.core.debug.gui.interpreters;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.dbg.target.TargetInterpreter;

public class DebuggerWrappedInterpreterConnection
		extends AbstractDebuggerWrappedConsoleConnection<TargetInterpreter> {

	public DebuggerWrappedInterpreterConnection(DebuggerInterpreterPlugin plugin,
			TargetInterpreter interpreter) {
		super(plugin, interpreter);
	}

	@Override
	public void setConsole(InterpreterConsole guiConsole) {
		super.setConsole(guiConsole);
		guiConsole.setPrompt(targetConsole.getPrompt());
	}

	@Override
	protected CompletableFuture<Void> sendLine(String line) {
		return targetConsole.execute(line);
	}
}
