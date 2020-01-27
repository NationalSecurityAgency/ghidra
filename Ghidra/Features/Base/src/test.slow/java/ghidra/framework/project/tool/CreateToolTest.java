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
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * This driver tests the following requirements:
 * (1) create a new empty tool
 * (2) create a tool from a named ToolConfig description
 */
public class CreateToolTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGTest.getTestDirectoryPath();

	private Project project;
	private PluginTool tool;

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

	private void closeTool(final PluginTool theTool) {
		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				theTool.close();
			}
		});

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindows();
	}

	/*
	 * Do the test.
	 * This doTest() routine tests the following requirements:
	 * (1) create (launch) an empty tool in the active workspace
	 * (2) launch a named tool from the project toolchest in the active workspace
	 *
	 * @param args[0] directory name (location) for project
	 * @param args[1] basename of the project
	 * @param args[2] [optional] name of tool to launch; not used when testing
	 * the requirement to create a new empty tool
	 */
	@Test
	public void testCreateTool() throws Exception {

		boolean verified = false;
		runSwing(new Runnable() {
			@Override
			public void run() {
				tool = ProjectTestUtils.getTool(project, null);
			}
		});
		try {
			// verify the tool is actually running before declaring success
			ToolManager tm = project.getToolManager();
			PluginTool[] runningTools = tm.getRunningTools();
			for (int t = 0; !verified && t < runningTools.length; t++) {
				if (runningTools[t].equals(tool)) {
					verified = true;
				}
			}
		}
		finally {
			closeTool(tool);
		}

		// report test results
		if (!verified) {
			Assert.fail("Create Tool test FAILED!!");
		}
	}

}
