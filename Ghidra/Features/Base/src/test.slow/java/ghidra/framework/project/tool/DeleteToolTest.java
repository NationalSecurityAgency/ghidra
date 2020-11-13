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

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * The following tests are performed in this test driver for
 * the new front end:
 * (1) delete a non-running tool from the user's project space
 * (2) delete a running tool from the user's project space
 */
public class DeleteToolTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String PROJECT_DIRECTORY = AbstractGTest.getTestDirectoryPath();
	private final static String TOOL_NAME = "TestTool";

	private PluginTool runningTool;
	private Project project;

	@Before
	public void setUp() throws Exception {
		ProjectTestUtils.deleteProject(PROJECT_DIRECTORY, PROJECT_NAME);
		project = ProjectTestUtils.getProject(PROJECT_DIRECTORY, PROJECT_NAME);
	}

	@After
	public void tearDown() throws Exception {
		project.close();
		ProjectTestUtils.deleteProject(PROJECT_DIRECTORY, PROJECT_NAME);
	}

	/*
	 * Tsts the following requirements:
	 * (1) delete a non-running tool from the user's project space
	 * (2) delete a running tool from the user's project space
	 *
	 * @param args same as args to main()
	 */
	@Test
	public void testDeleteTool() throws Exception {

		ToolChest toolChest = project.getLocalToolChest();

		// Make sure old tool instance does not exist
		toolChest.remove(TOOL_NAME);

		// create a new running tool
		runSwing(new Runnable() {
			@Override
			public void run() {
				runningTool = ProjectTestUtils.getTool(project, null);
			}
		});
		try {
			runningTool.setToolName(TOOL_NAME);

			// make sure tool config doesn't already exist in tool chest
			// to validate our test
			if (toolChest.getToolTemplate(TOOL_NAME) != null) {
				Assert.fail("Tool should not have been saved yet");
			}

			// save it to the tool chest
			ToolTemplate toolTemplate = runningTool.saveToolToToolTemplate();
			toolChest.addToolTemplate(toolTemplate);

			// now remove the tool config
			if (!toolChest.remove(TOOL_NAME)) {
				Assert.fail("Delete Tool FAILED: remove returned false when removing " + TOOL_NAME);
			}

			//
			// verify the tool is no longer in the project toolchest
			//
			if (toolChest.getToolTemplate(TOOL_NAME) != null) {
				Assert.fail("Non-running tool: " + TOOL_NAME + " was not deleted as expected!!!");
			}
		}
		finally {
			runSwing(new Runnable() {
				@Override
				public void run() {
					runningTool.close();
				}
			});
		}
	}

}
