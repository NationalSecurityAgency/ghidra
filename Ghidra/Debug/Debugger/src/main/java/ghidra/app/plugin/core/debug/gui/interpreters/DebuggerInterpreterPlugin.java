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

import java.util.HashMap;
import java.util.Map;

import javax.swing.SwingUtilities;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.app.services.DebuggerInterpreterService;
import ghidra.dbg.target.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo( //
		shortDescription = "Debugger interpreter panel service", //
		description = "Manage interpreter panels within debug sessions", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		servicesRequired = { //
			InterpreterPanelService.class //
		}, //
		servicesProvided = {
			DebuggerInterpreterService.class //
		} //
)
public class DebuggerInterpreterPlugin extends AbstractDebuggerPlugin
		implements DebuggerInterpreterService {

	@AutoServiceConsumed
	protected InterpreterPanelService consoleService;

	protected final Map<TargetObject, InterpreterConsole> consoles = new HashMap<>();

	public DebuggerInterpreterPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void showConsole(TargetConsole<?> targetConsole) {
		InterpreterConsole console;
		synchronized (consoles) {
			console = consoles.computeIfAbsent(targetConsole, c -> createConsole(targetConsole));
		}
		console.show();
	}

	@Override
	public void showConsole(TargetInterpreter<?> targetInterpreter) {
		InterpreterConsole console;
		synchronized (consoles) {
			console =
				consoles.computeIfAbsent(targetInterpreter, c -> createConsole(targetInterpreter));
		}
		console.show();
	}

	protected void disableConsole(TargetObject targetConsole, InterpreterConsole guiConsole) {
		InterpreterConsole old = consoles.get(targetConsole);
		assert old == guiConsole;
		SwingUtilities.invokeLater(() -> {
			if (guiConsole.isInputPermitted()) {
				guiConsole.setInputPermitted(false);
				guiConsole.setTransient();
				guiConsole.setPrompt(">>INVALID<<");
				/**
				 * TODO: Should invisible ones just be removed?
				 * 
				 * TODO: Would like setTransient to work like other providers, but
				 * InterpreterComponentProvider overrides it.... For now, I leave invisible disabled
				 * ones in the tool. User must show and click custom "remove interpreter" action.
				 */
				/*if (!console.isVisible()) {
					console.dispose();
				}*/
			}
		});
	}

	protected InterpreterConsole createConsole(
			AbstractDebuggerWrappedConsoleConnection<?> connection) {
		InterpreterConsole console = consoleService.createInterpreterPanel(connection, true);
		connection.setConsole(console);
		connection.runInBackground();
		return console;
	}

	protected InterpreterConsole createConsole(TargetConsole<?> targetConsole) {
		return createConsole(new DebuggerWrappedConsoleConnection(this, targetConsole));
	}

	protected InterpreterConsole createConsole(TargetInterpreter<?> targetInterpreter) {
		return createConsole(new DebuggerWrappedInterpreterConnection(this, targetInterpreter));
	}
}
