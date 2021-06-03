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

import java.io.IOException;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Test class for adding and removing workspaces from the current project,
 * renaming a workspace, and setting a workspace to be active.
 */
public class CreateWorkspaceTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGenericTest.getTestDirectoryPath();

	private Project project;

	/**
	 * Constructor
	 * @param arg0
	 */
	public CreateWorkspaceTest() {
		super();
	}

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
				project.close();
			}
		});
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	/**
	 * Do the test.
	 * @param args same args that are passed to RegressionTester.main()
	 */
	@Test
	public void testCreateWorkspace() throws Exception {

		// get project (create it if it doesn't exist...)

		ToolManager tm = project.getToolManager();
		String userName = SystemUtilities.getUserName();

		tm.createWorkspace(userName);

		try {
			tm.createWorkspace(userName);
			Assert.fail("Should have gotten DuplicateNameException for " + userName);
		}
		catch (DuplicateNameException e) {
			// expected
		}

		tm.createWorkspace(userName + "(1)");
		tm.createWorkspace(userName + "(2)");

		// get list of workspaces...
		Workspace[] wspaces = tm.getWorkspaces();
		for (Workspace wspace : wspaces) {
			System.out.println("Found workspace " + wspace.getName());
		}

		// should have 4 workspaces now: the default workspace, the username,
		// username(1) and username(2)
		assertEquals(4, wspaces.length);
		assertEquals("Workspace", wspaces[0].getName());
		assertEquals(userName, wspaces[1].getName());
		assertEquals(userName + "(1)", wspaces[2].getName());
		assertEquals(userName + "(2)", wspaces[3].getName());

		// now delete one workspace
		tm.removeWorkspace(wspaces[2]); // 3rd workspace is username(1)

		wspaces = tm.getWorkspaces();
		assertEquals(3, wspaces.length);

		for (Workspace wspace : wspaces) {
			if (wspace.getName().equals(userName + "(1)")) {
				Assert.fail("Should have deleted workspace " + wspace.getName());
			}
		}

		try {
			// now rename workspace to an existing name
			wspaces[0].setName(userName);
			Assert.fail("DuplicateNameException expected");
		}
		catch (DuplicateNameException e) {
			// expected
		}

		wspaces[1].setName("WORKSPACE-1");
		assertEquals("WORKSPACE-1", wspaces[1].getName());

		// now add a launch a tool in the workspace
		setWorkspaceActive(wspaces[0]);

		final Workspace workspace = wspaces[0];
		runSwing(new Runnable() {
			@Override
			public void run() {
				workspace.createTool();
			}
		});

		PluginTool[] runningTools = wspaces[0].getTools();
		assertEquals(1, runningTools.length);

		setWorkspaceActive(wspaces[1]);

		runningTools = wspaces[0].getTools();

		project.save();

		runSwing(new Runnable() {
			@Override
			public void run() {
				project.close();
			}
		});

		// now restore it
		runSwing(new Runnable() {
			@Override
			public void run() {
				try {
					project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME);
				}
				catch (LockException exc) {
					exc.printStackTrace();
					Assert.fail();
				}
				catch (IOException exc) {
					exc.printStackTrace();
					Assert.fail();
				}
			}
		});

		tm = project.getToolManager();
		wspaces = tm.getWorkspaces();
		for (Workspace wspace : wspaces) {
			System.out.println("** Workspace " + wspace.getName());
		}

		assertEquals(3, wspaces.length);
		assertEquals("Workspace", wspaces[0].getName());
		assertEquals("WORKSPACE-1", wspaces[1].getName());
		assertEquals(userName + "(2)", wspaces[2].getName());

		assertEquals(wspaces[1], tm.getActiveWorkspace());

	}

	private void setWorkspaceActive(final Workspace workspace) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				workspace.setActive();
			}
		});
	}
}
