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

import static org.junit.Assert.*;

import java.io.*;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.console.ConsolePlugin;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests the Python script functionality.
 */
public class PythonScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ConsoleService console;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		GhidraScriptUtil.initialize(new BundleHost(), null);
		tool.addPlugin(ConsolePlugin.class.getName());
		console = tool.getService(ConsoleService.class);
	}

	@After
	public void tearDown() throws Exception {
		GhidraScriptUtil.dispose();
		env.dispose();
	}

	/**
	 * Tests that Python scripts are running correctly.
	 * 
	 * @throws Exception If an exception occurred while trying to run the script.
	 */
	@Test
	public void testPythonScript() throws Exception {
		String script = "ghidra_scripts/python_basics.py";
		try {
			String output = runPythonScript(Application.getModuleFile("Python", script));
			assertTrue(output.contains("Snoopy"));
		}
		catch (FileNotFoundException e) {
			fail("Could not find python script: " + script);
		}
		catch (Exception e) {
			fail("Exception occurred trying to run script: " + e.getMessage());
		}
	}

	/**
	 * Tests that Python scripts are running correctly.
	 * 
	 * @throws Exception If an exception occurred while trying to run the script.
	 */
	@Test
	public void testPythonInterpreterGoneFromState() throws Exception {
		String script = "ghidra_scripts/python_basics.py";
		try {
			GhidraState state =
				new GhidraState(env.getTool(), env.getProject(), null, null, null, null);
			runPythonScript(Application.getModuleFile("Python", script), state);
			assertTrue(state.getEnvironmentVar(PythonScript.PYTHON_INTERPRETER) == null);
		}
		catch (FileNotFoundException e) {
			fail("Could not find python script: " + script);
		}
		catch (Exception e) {
			fail("Exception occurred trying to run script: " + e.getMessage());
		}
	}

	/**
	 * Runs the given Python script.
	 * 
	 * @param scriptFile The Python script to run.
	 * @return The console output of the script.
	 * @throws Exception If an exception occurred while trying to run the script.
	 */
	private String runPythonScript(ResourceFile scriptFile) throws Exception {
		GhidraState state =
			new GhidraState(env.getTool(), env.getProject(), null, null, null, null);
		return runPythonScript(scriptFile, state);
	}

	/**
	 * Runs the given Python script with the given initial state.
	 * 
	 * @param scriptFile The Python script to run.
	 * @param state The initial state of the script.
	 * @return The console output of the script.
	 * @throws Exception If an exception occurred while trying to run the script.
	 */
	private String runPythonScript(ResourceFile scriptFile, GhidraState state) throws Exception {

		runSwing(() -> console.clearMessages());

		PythonScriptProvider scriptProvider = new PythonScriptProvider();
		PrintWriter writer = new PrintWriter(new ByteArrayOutputStream());
		PythonScript script = (PythonScript) scriptProvider.getScriptInstance(scriptFile, writer);
		script.set(state, TaskMonitor.DUMMY, writer);
		script.run();

		waitForSwing();

		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> {
			String text = console.getText(0, console.getTextLength());
			ref.set(text);
		});

		String text = ref.get();
		return text;
	}
}
