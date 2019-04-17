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

import static org.junit.Assert.fail;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.project.test.TestProjectManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ProjectTestUtils;

/**
 * Test class for creating a project.
 */
public class CreateProjectTest extends AbstractGhidraHeadedIntegrationTest {

	private String testDir;

	@Before
	public void setUp() throws Exception {
		testDir = getTestDirectoryPath();
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME);

	}

	@After
	public void tearDown() throws Exception {
		ProjectTestUtils.deleteProject(testDir, PROJECT_NAME);
	}

	@Test
	public void testCreateProject() throws Exception {

		ProjectLocator url = new ProjectLocator(testDir, PROJECT_NAME);
		ProjectManager pm = TestProjectManager.get();

		try {
			pm.deleteProject(url);
		}
		catch (Exception e) {
			// don't exist; don't care
		}

		Project project = pm.createProject(url, null, true);
		if (project == null) {
			Assert.fail("project is null!!!");
			return;
		}

		ProjectLocator p = project.getProjectLocator();

		if (p == null) {
			fail("Project URL for " + project.getName() + " is null!");
		}

		ToolChest tc = project.getLocalToolChest();
		if (tc == null) {
			fail("tool chest is null!!!");
		}
		ToolManager tm = project.getToolManager();
		if (tm == null) {
			fail("tool manager is null!!!");
		}

		project.close();
	}

}
