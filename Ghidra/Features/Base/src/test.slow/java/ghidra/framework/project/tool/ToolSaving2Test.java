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
package ghidra.framework.project.tool;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.framework.plugintool.PluginTool;

public class ToolSaving2Test extends AbstractToolSavingTest {

	// tests that we've changed into manual save mode and that we can get back into auto save mode
	// in the right conditions
	@Test
	public void testRevertToAutoSave() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);
		setBooleanFooOptions(tool2, !isSet);
		closeToolAndManuallySave(tool1);

		// we are now in manual mode...

		// ...turn off manual mode by saving with only one tool open...
		saveTool(tool2);

		// ...change the tool again...
		isSet = getBooleanFooOptions(tool2);
		setBooleanFooOptions(tool2, !isSet);

		// ...now closing the tool should not give us a prompt
		closeToolWithNoSaveDialog(tool2);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);

		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	// test that with two changed tools and save one, then close in opposite order without saving.
	@Test
	public void testTwoToolsBothChanged_save1_closeBothOtherOrder() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);
		setBooleanFooOptions(tool2, !isSet);
		saveTool(tool1);

		closeToolAndManuallySave(tool2);
		closeToolWithNoSaveDialog(tool1);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}

	@Test
	public void testTwoToolsBothChanged_saveBoth_changeOneAgain_closeBoth() {
		PluginTool tool1 = launchTool(DEFAULT_TEST_TOOL_NAME);
		PluginTool tool2 = launchTool(DEFAULT_TEST_TOOL_NAME);

		boolean isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);
		setBooleanFooOptions(tool2, !isSet);
		saveTool(tool1);
		saveTool(tool2);

		isSet = getBooleanFooOptions(tool1);
		setBooleanFooOptions(tool1, !isSet);

		closeToolWithNoSaveDialog(tool2);
		closeToolAndManuallySave(tool1);

		PluginTool newTool = launchTool(DEFAULT_TEST_TOOL_NAME);
		assertEquals("Changed tool was not saved", !isSet, getBooleanFooOptions(newTool));
	}
}
