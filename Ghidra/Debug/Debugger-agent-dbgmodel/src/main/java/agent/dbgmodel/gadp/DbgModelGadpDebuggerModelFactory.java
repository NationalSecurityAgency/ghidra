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
package agent.dbgmodel.gadp;

import agent.dbgeng.gadp.DbgEngGadpDebuggerModelFactory;
import ghidra.dbg.util.ConfigurableFactory.FactoryDescription;
import ghidra.program.model.listing.Program;

@FactoryDescription(
	brief = "MS dbgmodel.dll (WinDbg Preview) via GADP/TCP",
	htmlDetails = """
			Connect to the Microsoft Debug Model.
			This is the same engine that powers WinDbg 2.
			This will protect Ghidra's JVM by using a subprocess to access the native API.""")
public class DbgModelGadpDebuggerModelFactory extends DbgEngGadpDebuggerModelFactory {

	@Override
	protected String getThreadName() {
		return "Local dbgmodel.dll Agent stdout";
	}

	@Override
	protected Class<?> getServerClass() {
		return DbgModelGadpServer.class;
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
		return 50;
	}
}
