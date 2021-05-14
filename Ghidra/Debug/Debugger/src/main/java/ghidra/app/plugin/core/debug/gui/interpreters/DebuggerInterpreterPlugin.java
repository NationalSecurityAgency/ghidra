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
import ghidra.app.plugin.core.interpreter.*;
import ghidra.app.services.DebuggerInterpreterService;
import ghidra.dbg.target.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;

@PluginInfo(
	shortDescription = "Debugger interpreter panel service",
	description = "Manage interpreter panels within debug sessions",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	servicesRequired = {
		InterpreterPanelService.class,
	},
	servicesProvided = {
		DebuggerInterpreterService.class,
	})
public class DebuggerInterpreterPlugin extends AbstractDebuggerPlugin
		implements DebuggerInterpreterService {

	@AutoServiceConsumed
	protected InterpreterPanelService consoleService;

	protected final Map<TargetObject, DebuggerInterpreterConnection> connections = new HashMap<>();

	public DebuggerInterpreterPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public DebuggerInterpreterConnection showConsole(TargetConsole targetConsole) {
		DebuggerInterpreterConnection conn;
		synchronized (connections) {
			conn = connections.computeIfAbsent(targetConsole, c -> createConnection(targetConsole));
		}
		conn.getInterpreterConsole().show();
		return conn;
	}

	@Override
	public DebuggerInterpreterConnection showConsole(TargetInterpreter targetInterpreter) {
		DebuggerInterpreterConnection conn;
		synchronized (connections) {
			conn = connections.computeIfAbsent(targetInterpreter,
				c -> createConnection(targetInterpreter));
		}
		conn.getInterpreterConsole().show();
		return conn;
	}

	protected void disableConsole(TargetObject targetConsole, InterpreterConsole guiConsole) {
		DebuggerInterpreterConnection old;
		synchronized (connections) {
			old = connections.remove(targetConsole);
		}
		assert old.getInterpreterConsole() == guiConsole;
		SwingUtilities.invokeLater(() -> {
			if (guiConsole.isInputPermitted()) {
				guiConsole.setInputPermitted(false);
				guiConsole.setTransient();
				guiConsole.setPrompt(">>INVALID<<");
			}
		});
	}

	protected void createConsole(AbstractDebuggerWrappedConsoleConnection<?> connection) {
		//InterpreterConsole console = consoleService.createInterpreterPanel(connection, true);
		// TODO: Just fix the console plugin
		InterpreterConsole console = new DebuggerInterpreterProvider(
			(InterpreterPanelPlugin) consoleService, connection, true);
		connection.setConsole(console);
		connection.runInBackground();
	}

	protected DebuggerInterpreterConnection createConnection(TargetConsole targetConsole) {
		DebuggerWrappedConsoleConnection conn =
			new DebuggerWrappedConsoleConnection(this, targetConsole);
		createConsole(conn);
		return conn;
	}

	protected DebuggerInterpreterConnection createConnection(
			TargetInterpreter targetInterpreter) {
		DebuggerWrappedInterpreterConnection conn =
			new DebuggerWrappedInterpreterConnection(this, targetInterpreter);
		createConsole(conn);
		return conn;
	}

	public void destroyConsole(TargetObject targetConsole, InterpreterConsole guiConsole) {
		DebuggerInterpreterConnection old;
		synchronized (connections) {
			old = connections.remove(targetConsole);
		}
		assert old.getInterpreterConsole() == guiConsole;
		SwingUtilities.invokeLater(() -> {
			guiConsole.dispose();
		});
	}
}
