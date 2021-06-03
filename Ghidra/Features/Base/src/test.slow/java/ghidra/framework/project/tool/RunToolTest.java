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
 * The following tests are performed in this test driver for
 * the new front end:
 * (1) Run Project Tool Without Data
 * (2) Run Tool imported from User Space
 */
public class RunToolTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGTest.getTestDirectoryPath();
	private final static String TOOL_NAME = "TestTool";

	private Project project;
	private PluginTool runningTool;
	private PluginTool tool;

	@Before
	public void setUp() throws Exception {
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
		project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	@After
	public void tearDown() throws Exception {
		runSwing(new Runnable() {
			@Override
			public void run() {
				project.save();
				project.close();
			}
		});
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	/*
	 * Do the test.
	 * This doTest() routine tests the following requirements:
	 * (1) Run Project Tool Without Data
	 * (2) Run Project Tool With Specified Data
	 * (3) Run Tool imported from User Space
	 * (running a new tool with and without data is done via ChangeToolData)
	 */
	@Test
	public void testRunTool() throws Exception {

		// Make sure old tool instance does not exist since it is not stored within the project
		ProjectTestUtils.deleteTool(project, TOOL_NAME);

		// Create tool and save tool config
		runSwing(new Runnable() {
			@Override
			public void run() {
				tool = ProjectTestUtils.getTool(project, null);
				tool.setToolName(TOOL_NAME);
			}
		});

		try {

			final ToolTemplate toolConfig = ProjectTestUtils.saveTool(project, tool);
			runSwing(new Runnable() {
				@Override
				public void run() {
					tool.close();
				}
			});

			//
			// TEST 1: launch the tool without data
			//
			ToolManager tm = project.getToolManager();

			// first get the active workspace that will contain the tool
			Workspace[] workspaces = tm.getWorkspaces();

			// the front end will know which one is the active one; just
			// use the first one for the test
			final Workspace activeWorkspace = workspaces[0];

			runSwing(new Runnable() {
				@Override
				public void run() {
					runningTool = activeWorkspace.runTool(toolConfig);
				}
			});
			assertNotNull(runningTool);
			runSwing(new Runnable() {
				@Override
				public void run() {
					runningTool.close();
				}
			});

		}
		finally {
			// Don't leave the tool in the tool chest
			runSwing(new Runnable() {
				@Override
				public void run() {
					ProjectTestUtils.deleteTool(project, TOOL_NAME);
				}
			});
		}

	}

}
