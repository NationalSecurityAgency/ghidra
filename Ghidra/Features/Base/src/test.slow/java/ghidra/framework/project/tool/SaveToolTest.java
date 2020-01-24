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

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * Test for creating a new empty tool with the new front end
 */
public class SaveToolTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGTest.getTestDirectoryPath();
	private final static String TOOL_NAME = "TestTool";

	private PluginTool runningTool;
	private Project project;

	@Before
	public void setUp() throws Exception {
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
		project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	@After
	public void tearDown() throws Exception {
		project.close();
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	/*
	 * This tests the following requirements:
	 * (1) create an empty tool in the active workspace, and
	 * (2) that duplicate project names do not throw exceptions.
	 */
	@Test
	public void testSaveTool() throws Exception {

		// Make sure old tool instance does not exist
		ToolChest toolChest = project.getLocalToolChest();
		toolChest.remove(TOOL_NAME);

		// create a new running tool
		runSwing(new Runnable() {
			@Override
			public void run() {
				runningTool = ProjectTestUtils.getTool(project, null);
			}
		});

		ToolTemplate toolTemplate = null;
		try {

			// set the name of the tool to what the user will enter in a "Save" dialog
			runningTool.setToolName(TOOL_NAME);

			// save the tool to the project tool chest
			ProjectTestUtils.saveTool(project, runningTool);

			// verify the project tool chest now contains the saved tool
			toolTemplate = toolChest.getToolTemplate(TOOL_NAME);
			if (toolTemplate == null) {
				Assert.fail(TOOL_NAME + " was not saved to tool chest!");
				return;
			}

			toolChest.addToolTemplate(toolTemplate);

			// verify the new name is different than the original name
			assertTrue("The tool config's name was not changed when adding a tool with a " +
				"duplicate name.", !TOOL_NAME.equals(toolTemplate.getName()));
		}
		finally {
			runSwing(new Runnable() {
				@Override
				public void run() {
					runningTool.close();
				}
			});

			toolChest.remove(TOOL_NAME);
			ProjectTestUtils.deleteTool(project, TOOL_NAME);
			if (toolTemplate != null) {
				toolChest.remove(toolTemplate.getName());
				ProjectTestUtils.deleteTool(project, toolTemplate.getName());
			}
		}
	}
}
