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
package agent.lldb.gadp;

import java.util.List;

import ghidra.dbg.gadp.server.AbstractGadpLocalDebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.util.classfinder.ExtensionPointProperties;

@FactoryDescription( //
	brief = "LLVM lldb local agent via GADP/TCP", //
	htmlDetails = "Launch a new agent using LLVM's lldb." //
)
@ExtensionPointProperties(priority = 100)
public class LldbLocalDebuggerModelFactory extends AbstractGadpLocalDebuggerModelFactory {

	protected String remote = "none"; // Require user to start server
	@FactoryOption("DebugConnect options (.server)")
	public final Property<String> agentRemoteOption =
		Property.fromAccessors(String.class, this::getAgentRemote, this::setAgentRemote);

	protected String transport = "none"; // Require user to start server
	@FactoryOption("Remote process server options (untested)")
	public final Property<String> agentTransportOption =
		Property.fromAccessors(String.class, this::getAgentTransport, this::setAgentTransport);

	@Override
	public boolean isCompatible() {
		String osname = System.getProperty("os.name");
		return osname.contains("Mac OS X") || osname.contains("Linux") || osname.contains("Windows");
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

	@Override
	protected String getThreadName() {
		return "Local LLDB Agent stdout";
	}

	protected Class<?> getServerClass() {
		return LldbGadpServer.class;
	}

	@Override
	protected void completeCommandLine(List<String> cmd) {
		cmd.add(getServerClass().getCanonicalName());
		cmd.addAll(List.of("-H", host));
		cmd.addAll(List.of("-p", Integer.toString(port)));
	}
}
