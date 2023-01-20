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
import ghidra.program.model.listing.Program;

@FactoryDescription(
	brief = "lldb via GADP",
	htmlDetails = """
			Connect to lldb.
			This is best for most macOS and iOS targets, but supports many others.
			This will protect Ghidra's JVM by using a subprocess to access the native API.""")
public class LldbGadpDebuggerModelFactory extends AbstractGadpLocalDebuggerModelFactory {

	@Override
	public int getPriority(Program program) {
		String osname = System.getProperty("os.name").toLowerCase();
		if (!(osname.contains("mac os x") || osname.contains("linux") ||
			osname.contains("windows"))) {
			return -1;
		}
		if (program != null) {
			String exe = program.getExecutablePath();
			if (exe == null || exe.isBlank()) {
				return -1;
			}
		}
		return 35;
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
