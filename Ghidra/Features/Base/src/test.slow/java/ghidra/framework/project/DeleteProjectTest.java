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

import java.io.File;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.project.test.TestProjectManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * Test for Close and Delete a project.
 */
public class DeleteProjectTest extends AbstractGhidraHeadedIntegrationTest {

	private ProjectManager pm;
	private ProjectLocator url;
	private String testDir;

	@Before
	public void setUp() throws Exception {
		testDir = getTestDirectoryPath();
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME);
		pm = TestProjectManager.get();

		// get project (create it if it doesn't exist...)
		Project project = ProjectTestUtils.getProject(testDir, PROJECT_NAME);
		url = project.getProjectLocator();
		project.close();
	}

	@Test
	public void testDeleteProject() throws Exception {

		// how to tell whether the project was closed???

		Assert.assertTrue("Did not delete project " + url, pm.deleteProject(url));

		// check the file system...
		File file = new File(testDir, PROJECT_NAME);
		if (file.exists()) {
			Assert.fail("Did not delete the directory for " + url);
		}

	}

}
