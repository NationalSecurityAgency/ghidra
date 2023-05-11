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
package agent.dbgeng;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.impl.DbgModelImpl;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.program.model.listing.Program;

@FactoryDescription(
	brief = "MS dbgeng.dll (WinDbg)",
	htmlDetails = """
			Connect to the Microsoft Debug Engine.
			This is the same engine that powers WinDbg.
			This is best for most Windows userspace and kernel targets.
			Kernel debugging is still experimental.
			This will access the native API, which may put Ghidra's JVM at risk.""")
public class DbgEngInJvmDebuggerModelFactory implements DebuggerModelFactory {

	protected String remote = "none"; // Require user to start server
	@FactoryOption("DebugConnect options (.server)")
	public final Property<String> agentRemoteOption =
		Property.fromAccessors(String.class, this::getAgentRemote, this::setAgentRemote);

	protected String transport = "none"; // Require user to start server
	@FactoryOption("Remote process server options (untested)")
	public final Property<String> agentTransportOption =
		Property.fromAccessors(String.class, this::getAgentTransport, this::setAgentTransport);

	@Override
	public CompletableFuture<? extends DebuggerObjectModel> build() {
		DbgModelImpl model = new DbgModelImpl();
		List<String> cmds = new ArrayList<>();
		completeCommandLine(cmds);
		return model.startDbgEng(cmds.toArray(new String[cmds.size()])).thenApply(__ -> model);
	}

	@Override
	public int getPriority(Program program) {
		// TODO: Might instead look for the DLL
		if (!System.getProperty("os.name").toLowerCase().contains("windows")) {
			return -1;
		}
		if (program != null) {
			String exe = program.getExecutablePath();
			if (exe == null || exe.isBlank()) {
				return -1;
			}
		}
		return 80;
	}

	public String getAgentTransport() {
		return transport;
	}

	public void setAgentTransport(String transport) {
		this.transport = transport;
	}

	public String getAgentRemote() {
		return remote;
	}

	public void setAgentRemote(String remote) {
		this.remote = remote;
	}

	protected void completeCommandLine(List<String> cmd) {
		if (!remote.equals("none") && !remote.equals("")) {
			cmd.addAll(List.of(remote));
		}
		if (!transport.equals("none") && !transport.equals("")) {
			cmd.addAll(List.of(transport));
		}
	}
}
