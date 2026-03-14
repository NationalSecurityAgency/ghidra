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
package ghidra.electron.headless;

import static org.junit.Assert.*;

import java.nio.file.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ProjectStoreTest extends AbstractGenericTest {

	@Test
	public void testCreateListAndOpenProject() throws Exception {
		Path tempDir = createTempDirectory("headless-project-store");
		EventBroker broker = new EventBroker();
		ProjectStore store = new ProjectStore(tempDir, new FakeProjectOps(), broker);

		ProjectRecord created = store.createProject(tempDir.toString(), "alpha");
		assertNotNull(created.projectId);
		assertEquals(1, store.listProjects().size());

		ProjectRecord opened = store.openProjectById(created.projectId);
		assertTrue(opened.isActive);
		assertNotNull(opened.lastOpenedAt);
	}

	@Test
	public void testCreatedProjectsPersistAcrossStoreReload() throws Exception {
		Path tempDir = createTempDirectory("headless-project-store-persist");
		EventBroker broker = new EventBroker();
		ProjectStore originalStore = new ProjectStore(tempDir, new FakeProjectOps(), broker);

		ProjectRecord created = originalStore.createProject(tempDir.toString(), "persisted-project");

		ProjectStore reloadedStore = new ProjectStore(tempDir, new FakeProjectOps(), broker);
		assertEquals(1, reloadedStore.listProjects().size());
		ProjectRecord remembered = reloadedStore.getProject(created.projectId);
		assertEquals("persisted-project", remembered.name);
		assertEquals(created.projectPath, remembered.projectPath);
	}
}
