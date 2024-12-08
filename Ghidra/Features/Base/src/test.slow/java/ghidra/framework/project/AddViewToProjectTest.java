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
package ghidra.framework.project;

import static org.junit.Assert.*;

import java.net.URL;

import org.junit.*;

import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Test class for adding and a view to a project, and removing
 * the view from the project.
 */
public class AddViewToProjectTest extends AbstractGhidraHeadlessIntegrationTest {

	private final static String DIRECTORY_NAME = getTestDirectoryPath();
	private final static String PROJECT_NAME1 = "TestAddViewToProject";
	private final static String PROJECT_VIEW1 = "TestView1";
	private final static String PROJECT_VIEW2 = "TestView2";

	@Before
	public void setUp() throws Exception {

		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME1);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_VIEW1);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_VIEW2);
	}

	@After
	public void tearDown() throws Exception {
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME1);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_VIEW1);
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_VIEW2);
	}

	@Test
	public void testAddToView() throws Exception {

		// make sure we have projects to use as the project view...
		ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_VIEW1).close();
		ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_VIEW2).close();

		// get project (create it if it doesn't exist...)
		Project project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME1);

		try {
			URL view = GhidraURL.makeURL(DIRECTORY_NAME, PROJECT_VIEW1);
			project.addProjectView(view, true);

			// add another view that will be removed to test the remove
			project.addProjectView(GhidraURL.makeURL(DIRECTORY_NAME, PROJECT_VIEW2), true);

			// validate the view was added to project
			ProjectLocator[] projViews = project.getProjectViews();
			for (ProjectLocator projView : projViews) {
				Msg.debug(this, "** added view: " + projView);
			}

			// remove the view...
			project.removeProjectView(view);
			Msg.debug(this, "** removed view: " + view);

			projViews = project.getProjectViews();
			for (ProjectLocator projView : projViews) {
				if (view.equals(projView)) {
					Assert.fail("Found project view (" + view + ") that should have been removed!");
				}
			}
		}
		finally {
			project.close();
		}
	}

	@Test
	public void testCloseViewWithOpenProgram() throws Exception {

		DomainObject dobj = null;

		// make sure we have projects to use as the project view...
		Project project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_VIEW1);
		try {
			ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
			DomainFolder rootFolder = project.getProjectData().getRootFolder();
			rootFolder.createFile("Test", builder.getProgram(), TaskMonitor.DUMMY);
			builder.dispose();
			project.close();

			// get project (create it if it doesn't exist...)
			project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME1);

			URL view = GhidraURL.makeURL(DIRECTORY_NAME, PROJECT_VIEW1);
			DefaultProjectData projectData =
				(DefaultProjectData) project.addProjectView(view, true);
			Msg.debug(this, "** added view: " + view);
			assertNotNull(projectData);

			DomainFile f = projectData.getFile("/Test");
			assertNotNull(f);

			// Open file and hold onto
			dobj = f.getDomainObject(this, true, false, TaskMonitor.DUMMY);
			Msg.debug(this, "** opened program: " + f);

			assertFalse(projectData.isClosed());
			assertFalse(projectData.isDisposed());

			// remove the view while program open...
			project.removeProjectView(view);
			Msg.debug(this, "** removed view: " + view);

			assertTrue(projectData.isClosed());
			assertFalse(projectData.isDisposed());

			Msg.debug(this, "** releasing program: " + f);
			dobj.release(this);
			dobj = null;

			assertTrue(projectData.isClosed());
			assertTrue(projectData.isDisposed());
		}
		finally {
			if (dobj != null) {
				dobj.release(this);
			}
			project.close();
		}
	}

}
