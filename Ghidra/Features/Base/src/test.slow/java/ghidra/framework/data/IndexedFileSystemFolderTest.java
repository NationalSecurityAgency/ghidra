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
package ghidra.framework.data;

import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.InvalidNameException;

import java.io.File;
import java.io.IOException;

import org.junit.*;

public class IndexedFileSystemFolderTest extends AbstractGhidraHeadedIntegrationTest {

	private File testRootDir;
	private File privateProjectDir;
	private File sharedProjectDir;
	private DomainFolder root;
	private Project project;
	private LocalFileSystem sharedFS;
	private LocalFileSystem privateFS;

	public IndexedFileSystemFolderTest() {
	}

	@Before
	public void setUp() throws Exception {
		testRootDir = createTempDirectory("test_indexed_fs_folders");
		privateProjectDir = new File(testRootDir, "privateFS");
		sharedProjectDir = new File(testRootDir, "sharedFS");

		privateProjectDir.mkdir();
		sharedProjectDir.mkdir();

		privateFS = LocalFileSystem.getLocalFileSystem(privateProjectDir.getAbsolutePath(), true,
			true, false, false);
		sharedFS = LocalFileSystem.getLocalFileSystem(sharedProjectDir.getAbsolutePath(), true,
			true, false, false);
		ProjectFileManager projectFileManager = new ProjectFileManager(privateFS, sharedFS);
		root = projectFileManager.getRootFolder();
	}

	@After
	public void tearDown() {
		deleteTestFiles();
	}

	private void deleteTestFiles() {
		deleteAll(testRootDir);
	}

	private void deleteAll(File file) {
		if (file.isDirectory()) {
			File[] files = file.listFiles();
			for (int i = 0; i < files.length; i++) {
				deleteAll(files[i]);
			}
		}
		file.delete();
	}

	@Test
	public void test1() throws InvalidNameException, IOException {
		DomainFolder folder1 = root.createFolder("subfolder1");
		Assert.assertEquals("/subfolder1", folder1.getPathname());
	}

	/**
	 * Tests issue where DomainFolder.getFolder("") returns
	 * a malformed folder that will fail when used later.
	 * <p>
	 * @throws Exception
	 */
	@Test
	public void testGetBlankFolderName() throws Exception {

		DomainFolder folder1 = root.createFolder("a");
		DomainFolder folder2 = folder1.getFolder("");
		Assert.assertNull("Result from getFolder with empty param should be null", folder2);
	}

}
