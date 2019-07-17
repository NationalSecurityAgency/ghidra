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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class GhidraScriptMgrPlugin1Test extends AbstractGhidraScriptMgrPluginTest {

	public GhidraScriptMgrPlugin1Test() {
		super();
	}

	@Test
	public void testRunLastScriptAction() throws Exception {

		assertRunLastActionEnabled(false);

		//
		// Run a script once...
		//
		String initialScriptName = "HelloWorldScript.java";
		selectScript(initialScriptName);
		String fullOutput = runScript(initialScriptName);
		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		//
		// Run the script again
		//
		assertRunLastActionEnabled(true);
		fullOutput = runLastScript(initialScriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);

		//
		// Now select and run another script
		//
		String secondScriptName = "FormatExampleScript.java";
		selectScript(secondScriptName);
		fullOutput = runScript(secondScriptName);
		expectedOutput = "jumped over the";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		//
		// Run the script again
		//
		assertRunLastActionEnabled(true);
		fullOutput = runLastScript(secondScriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);
	}
}
