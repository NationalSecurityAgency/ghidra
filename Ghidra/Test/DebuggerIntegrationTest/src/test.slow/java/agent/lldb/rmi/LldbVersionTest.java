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
package agent.lldb.rmi;

import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;

public class LldbVersionTest extends AbstractGhidraHeadedDebuggerTest {

	List<String> toml;

	@Before
	public void read() throws IOException {
		toml = readToml("Debugger-agent-lldb");
	}

	@Test
	public void testTomlVersionConsistency() throws IOException {
		assertVersionMatchesApplication(parseVersionFromToml(toml));
	}

	@Test
	public void testTomlGhidratraceDepVersion() throws IOException {
		assertVersionMatchesApplication(parseGhidraTraceDepFromToml(toml));
	}
}
