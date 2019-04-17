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

import java.net.URL;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * Test class for adding and a view to a project, and removing
 * the view from the project.
 */
public class AddViewToProjectTest extends AbstractGhidraHeadlessIntegrationTest {

	private final static String DIRECTORY_NAME = AbstractGenericTest.getTestDirectoryPath();
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

	/**
	 * Do the test.
	 * @param args same args that are passed to RegressionTester.main()
	 */
	@Test
	public void testAddToView() throws Exception {

//        String filename =  System.getProperty("user.dir") +
//            File.separator + "testGhidraPreferences";
//
//        try {
//            Preferences.load(filename);
//
//        } catch (IOException e) {
//        }
//
//        Preferences.setFilename(filename);

		// make sure we have projects to use as the project view...
		ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_VIEW1).close();
		ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_VIEW2).close();

		// get project (create it if it doesn't exist...)
		Project project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME1);

		try {
			URL view = GhidraURL.makeURL(DIRECTORY_NAME, PROJECT_VIEW1);
			project.addProjectView(view);

			// add another view that will be removed to test the remove
			project.addProjectView(GhidraURL.makeURL(DIRECTORY_NAME, PROJECT_VIEW2));

			// validate the view was added to project
			ProjectLocator[] projViews = project.getProjectViews();
			for (ProjectLocator projView : projViews) {
				System.out.println("added view: " + projView);
			}

			// remove the view...
			project.removeProjectView(view);
			System.out.println("removed view: " + view);

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

}
