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

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.*;

import ghidra.framework.store.local.LocalFileSystem;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class GhidraFolderTest extends AbstractGhidraHeadedIntegrationTest {
	private File privateProjectDir;
	private File sharedProjectDir;
	private LocalFileSystem sharedFS;
	private LocalFileSystem privateFS;

	private GhidraFolder root;

	public GhidraFolderTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		File tempDir = createTempDirectory(getName());
		privateProjectDir = new File(tempDir, "privateFS");
		sharedProjectDir = new File(tempDir, "sharedFS");

		deleteTestFiles();

		privateProjectDir.mkdir();
		sharedProjectDir.mkdir();

		File f = new File(privateProjectDir, "a");
		f.mkdir();
		f = new File(f, "x");
		f.mkdir();

		f = new File(privateProjectDir, "b");
		f.mkdir();

		f = new File(sharedProjectDir, "a");
		f.mkdir();
		f = new File(f, "y");
		f.mkdir();
		f = new File(sharedProjectDir, "c");
		f.mkdir();

		// TODO: since we pre-populated the filesystem we must use as non-indexed filesystem
		privateFS = LocalFileSystem.getLocalFileSystem(privateProjectDir.getAbsolutePath(), false,
			false, false, true);
		sharedFS = LocalFileSystem.getLocalFileSystem(sharedProjectDir.getAbsolutePath(), false,
			true, false, true);
		ProjectFileManager projectFileManager = new ProjectFileManager(privateFS, sharedFS);
		root = projectFileManager.getRootFolder();
	}

	private void deleteTestFiles() {
		deleteAll(privateProjectDir);
		deleteAll(sharedProjectDir);
	}

	@After
	public void tearDown() {
		deleteTestFiles();
	}

	@Test
	public void testGetFolderNames() throws Exception {
		GhidraFolder[] folders = root.getFolders();
		assertEquals(3, folders.length);
		assertEquals("a", folders[0].getName());
		assertEquals("b", folders[1].getName());
		assertEquals("c", folders[2].getName());

		folders = folders[0].getFolders();
		assertEquals(2, folders.length);
		assertEquals("x", folders[0].getName());
		assertEquals("y", folders[1].getName());

	}

	// TODO: 
	@Test
	public void testFolderRename() throws Exception {

		root.getFolders();// force root visitation

		GhidraFolder folder = root.getFolder("a");
		assertNotNull(folder);

		folder.setName("foo");

		GhidraFolder[] folders = root.getFolders();
		assertEquals(3, folders.length);
		assertEquals("b", folders[0].getName());
		assertEquals("c", folders[1].getName());
		assertEquals("foo", folders[2].getName());

	}

	@Test
	public void testPrivateMoveTo() throws Exception {
		GhidraFolder aFolder = root.getFolder("a");
		GhidraFolder bFolder = root.getFolder("b");
		// move "b" to "a"
		bFolder = bFolder.moveTo(aFolder);
		GhidraFolder[] folders = root.getFolders();
		assertEquals(2, folders.length);

		assertNotNull(bFolder);
		assertEquals("/a/b", bFolder.getPathname());

		assertNull(root.getFolder("b"));
		assertEquals(aFolder, bFolder.getParent());

		assertTrue(privateFS.folderExists("/a/b"));
		assertTrue(!sharedFS.folderExists("/a/b"));
	}

	@Test
	public void testMovePrivateToShared() throws Exception {
		GhidraFolder bFolder = root.getFolder("b");
		GhidraFolder cFolder = root.getFolder("c");

		// move "b" to "c"
		bFolder = bFolder.moveTo(cFolder);
		GhidraFolder[] folders = root.getFolders();
		assertEquals(2, folders.length);

		assertNotNull(bFolder);
		assertEquals("/c/b", bFolder.getPathname());

		assertNull(root.getFolder("b"));

		assertEquals(cFolder, bFolder.getParent());
		assertTrue(privateFS.folderExists("/c/b"));
		assertTrue(!sharedFS.folderExists("/c/b"));
	}

	@Test
	public void testMovedSharedTo() throws Exception {
		GhidraFolder cFolder = root.getFolder("c");
		GhidraFolder dFolder = root.createFolder("d");

		dFolder = dFolder.moveTo(cFolder);

		assertNotNull(dFolder);
		assertEquals("/c/d", dFolder.getPathname());

		assertNull(root.getFolder("d"));

		assertEquals(cFolder, dFolder.getParent());
		assertTrue(privateFS.folderExists("/c/d"));
		assertTrue(!sharedFS.folderExists("/c/d"));

	}

	@Test
	public void testMoveShared2() throws Exception {
		GhidraFolder cFolder = root.getFolder("c");
		GhidraFolder dFolder = root.createFolder("d");

		cFolder = cFolder.moveTo(dFolder);

		assertNotNull(cFolder);
		assertEquals("/d/c", cFolder.getPathname());

		assertNull(root.getFolder("c"));

		assertEquals(dFolder, cFolder.getParent());
		assertTrue(!privateFS.folderExists("/d/c"));
		assertTrue(sharedFS.folderExists("/d/c"));

	}

	@Test
	public void testMoveTo3() throws Exception {
		GhidraFolder dFolder = root.createFolder("d");
		GhidraFolder aFolder = root.getFolder("a");

		aFolder = aFolder.moveTo(dFolder);

		assertEquals(dFolder, aFolder.getParent());
		assertTrue(privateFS.folderExists("/d/a"));
		assertTrue(sharedFS.folderExists("/d/a"));

	}

	@Test
	public void testCopyTo() throws Exception {
		System.err.println("folders.length: " + root.getFolders().length);

		GhidraFolder aFolder = root.getFolder("a");
		GhidraFolder bFolder = root.getFolder("b");

		aFolder.copyTo(bFolder, null);
		GhidraFolder[] folders = root.getFolders();
		if (folders.length != 3) {
			System.err.println("Folders of " + root.getName());
			for (GhidraFolder folder : folders) {
				System.err.println("\t" + folder);
			}
		}

		assertEquals(3, folders.length);

		folders = bFolder.getFolders();
		assertEquals(1, folders.length);

		assertEquals("a", folders[0].getName());

		folders = folders[0].getFolders();
		assertEquals(2, folders.length);
		assertEquals("x", folders[0].getName());

		assertTrue(privateFS.folderExists("/a/x"));
		assertTrue(privateFS.folderExists("/b/a/x"));
		assertTrue(privateFS.folderExists("/b/a/y"));

		assertTrue(sharedFS.folderExists("/a/y"));
		assertTrue(sharedFS.folderExists("/c"));
		assertTrue(!sharedFS.folderExists("/a/x"));
	}

	@Test
	public void testSetName() throws Exception {
		GhidraFolder aFolder = root.getFolder("a");
		aFolder = aFolder.setName("bigA");
		assertEquals("/bigA", aFolder.getPathname());
	}

	@Test
	public void testSetNameDuplicate() throws Exception {
		GhidraFolder aFolder = root.getFolder("a");
		try {
			aFolder.setName("c");
			Assert.fail("Should have gotten DuplicateFileException!");
		}
		catch (IOException e) {
			// expected
		}

	}

	@Test
	public void testToString() throws Exception {
		GhidraFolder aFolder = root.getFolder("a");
		GhidraFolder s1Folder = aFolder.createFolder("s1");
		GhidraFolder s2Folder = s1Folder.createFolder("s2");
		GhidraFolder s3Folder = s2Folder.createFolder("s3");

		assertEquals("Test:/", root.toString());
		assertEquals("Test:/a/s1/s2/s3", s3Folder.toString());
	}

	private void deleteAll(File file) {
		if (file.isDirectory()) {
			File[] files = file.listFiles();
			for (File file2 : files) {
				deleteAll(file2);
			}
		}
		file.delete();
	}

}
