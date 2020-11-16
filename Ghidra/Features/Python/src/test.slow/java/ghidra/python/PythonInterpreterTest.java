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

import java.io.ByteArrayOutputStream;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Tests the Ghidra python interpreter's functionality.
 */
public class PythonInterpreterTest extends AbstractGhidraHeadedIntegrationTest {

	private ByteArrayOutputStream out;
	private GhidraPythonInterpreter interpreter;

	@Before
	public void setUp() throws Exception {
		out = new ByteArrayOutputStream();
		GhidraScriptUtil.initialize(new BundleHost(), null);
		interpreter = GhidraPythonInterpreter.get();
		interpreter.setOut(out);
		interpreter.setErr(out);
	}

	@After
	public void tearDown() throws Exception {
		out.reset();
		interpreter.cleanup();
		GhidraScriptUtil.dispose();
	}

	/**
	 * Tests that the interpreter's "push" method is working by executing a simple line of python.
	 */
	@Test
	public void testPythonPush() {
		final String str = "hi";
		interpreter.push("print \"" + str + "\"", null);
		assertEquals(out.toString().trim(), str);
	}

	/**
	 * Tests that the interpreter's "execFile" method is working by executing a simple file of python.
	 */
	@Test
	public void testPythonExecFile() {
		interpreter.execFile(new ResourceFile("ghidra_scripts/python_basics.py"), null);
		assertTrue(out.toString().contains("Snoopy"));
	}

	/**
	 * Tests that our sitecustomize.py modules gets loaded by testing the custom help function
	 * that we install from there.
	 */
	@Test
	public void testPythonSiteCustomize() {
		interpreter.push("help", null);
		assertTrue(out.toString().contains("Press 'F1'"));
	}

	/**
	 * Tests that cleaning the interpreter invalidates it.
	 */
	@Test
	public void testPythonCleanupInvalidation() {
		interpreter.cleanup();

		try {
			interpreter.push("pass", null);
			fail("Push still worked after interpreter cleanup.");
		}
		catch (IllegalStateException e) {
			// If everything worked, we should end up here.
		}
	}
}
