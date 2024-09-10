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
package ghidra.pyghidra;

import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests the Python Plugin functionality.
 */
public class PyGhidraPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		PluginTool tool = env.getTool();
		GhidraScriptUtil.initialize(new BundleHost(), null);
		tool.addPlugin(PyGhidraPlugin.class.getName());
		env.getPlugin(PyGhidraPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		GhidraScriptUtil.dispose();
		env.dispose();
	}
}
