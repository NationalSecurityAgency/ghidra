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
package ghidra.python;

import static org.junit.Assert.assertNotSame;

import org.junit.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests the Python Plugin functionality.
 */
public class PythonPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private PythonPlugin plugin;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(PythonPlugin.class.getName());
		plugin = env.getPlugin(PythonPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/**
	 * Tests that issuing a reset from the plugin resets the interpreter.
	 */
	@Test
	public void testPythonPluginReset() {
		GhidraPythonInterpreter origInterpreter = plugin.getInterpreter();
		plugin.reset();
		GhidraPythonInterpreter newInterpreter = plugin.getInterpreter();
		assertNotSame(origInterpreter, newInterpreter);
	}
}
