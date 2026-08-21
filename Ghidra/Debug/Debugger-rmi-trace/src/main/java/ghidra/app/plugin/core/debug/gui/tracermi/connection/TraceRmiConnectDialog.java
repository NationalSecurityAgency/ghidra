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
package ghidra.app.plugin.core.debug.gui.tracermi.connection;

import java.util.Map;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLaunchDialog;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.framework.plugintool.PluginTool;

public class TraceRmiConnectDialog extends TraceRmiLaunchDialog {

	static final LaunchParameter<String> PARAM_ADDRESS =
		LaunchParameter.create(String.class, "address",
			"Host/Address", "Address or hostname for interface(s) to listen on",
			true, ValStr.str("localhost"), str -> str);
	static final LaunchParameter<Integer> PARAM_PORT =
		LaunchParameter.create(Integer.class, "port",
			"Port", "TCP port number, 0 for ephemeral",
			true, ValStr.from(0), Integer::decode);
	private static final Map<String, LaunchParameter<?>> PARAMETERS =
		LaunchParameter.mapOf(PARAM_ADDRESS, PARAM_PORT);

	public TraceRmiConnectDialog(PluginTool tool, String title, String buttonText) {
		super(tool, title, buttonText, DebuggerResources.ICON_CONNECTION);
	}

	public Map<String, ValStr<?>> promptArguments() {
		return promptArguments(PARAMETERS, Map.of(), Map.of());
	}
}
