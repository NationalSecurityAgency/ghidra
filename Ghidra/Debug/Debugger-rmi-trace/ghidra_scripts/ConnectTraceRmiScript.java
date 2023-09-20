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
import java.net.InetSocketAddress;
import java.util.Objects;

import ghidra.app.plugin.core.debug.service.rmi.trace.TraceRmiPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.TraceRmiService;

public class ConnectTraceRmiScript extends GhidraScript {

	TraceRmiService getService() throws Exception {
		TraceRmiService service = state.getTool().getService(TraceRmiService.class);
		if (service != null) {
			return service;
		}
		state.getTool().addPlugin(TraceRmiPlugin.class.getName());
		return Objects.requireNonNull(state.getTool().getService(TraceRmiService.class));
	}

	@Override
	protected void run() throws Exception {
		TraceRmiService service = getService();
		service.connect(new InetSocketAddress(askString("Trace RMI", "hostname", "localhost"),
			askInt("Trace RMI", "port")));
		println("Connected");

//		if (askYesNo("Execute?", "Execute 'echo test'?")) {
//			handler.getMethods().get("execute").invoke(Map.of("cmd", "script print('test')"));
//		}
	}
}
