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
import java.util.Map;
import java.util.Objects;

import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.TraceRmiService;
import ghidra.debug.api.tracermi.*;

public class ListenTraceRmiScript extends GhidraScript {

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

		TraceRmiAcceptor acceptor = service.acceptOne(null);
		println("Listening at " + acceptor.getAddress());
		TraceRmiConnection connection = acceptor.accept();
		println("Connection from " + connection.getRemoteAddress());

		RemoteMethod execute = connection.getMethods().get("execute");
		if (execute == null) {
			printerr("No execute method!");
		}
		while (true) {
			String cmd = askString("Execute", "command?");
			try {
				execute.invoke(Map.of("cmd", cmd));
			}
			catch (TraceRmiError e) {
				printerr(e.getMessage());
			}
		}
	}
}
