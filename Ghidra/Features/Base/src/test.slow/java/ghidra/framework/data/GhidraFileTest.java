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

import db.DBHandle;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;

public class GhidraFileTest extends AbstractGhidraHeadedIntegrationTest {
	private File privateProjectDir;
	private File sharedProjectDir;
	private FileSystem sharedFS;
	private LocalFileSystem privateFS;

	private ProjectFileManager pfm;
	private GhidraFolder root;

	public GhidraFileTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		File tempDir = createTempDirectory(getName());
		privateProjectDir = new File(tempDir, "privateFS");
		sharedProjectDir = new File(tempDir, "sharedFS");
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
		pfm = new ProjectFileManager(privateFS, sharedFS);
		root = pfm.getRootFolder();

	}

	@After
	public void tearDown() {
		deleteAll(privateProjectDir);
		deleteAll(sharedProjectDir);
	}

	@Test
	public void testFileID() throws IOException {
		createDB(privateFS, "/a", "file1");
		createDB(sharedFS, "/a", "file2");
		refresh();

		DomainFile df1 = root.getFolder("a").getFile("file1");
		assertNotNull(df1);
		String fileID1 = df1.getFileID();
		assertNotNull(fileID1);

		DomainFile df2 = root.getFolder("a").getFile("file2");
		assertNotNull(df2);
		String fileID2 = df2.getFileID();
		assertNotNull(fileID2);

		assertTrue(!fileID1.equals(fileID2));
	}

	@Test
	public void testMove() throws IOException {
		createDB(privateFS, "/a", "file");
		createDB(privateFS, "/b", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.moveTo(root.getFolder("b"));
		assertEquals("file.1", df.getName());
		assertEquals("/b/file.1", df.getPathname());
		df = root.getFolder("a").getFile("file");
		assertNull(df);
	}

	@Test
	public void testMove1() throws IOException {
		createDB(privateFS, "/a", "file");
		createDB(privateFS, "/b", "file");
		createDB(privateFS, "/b", "file.1");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.moveTo(root.getFolder("b"));
		assertEquals("file.2", df.getName());
	}

	@Test
	public void testMove2() throws IOException {
		createDB(privateFS, "/a", "file");
		createDB(sharedFS, "/b", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);

		assertTrue(!df.isHijacked());

		df = df.moveTo(root.getFolder("b"));
		assertEquals("file.1", df.getName());
	}

	@Test
	public void testMove3() throws IOException {
		createDB(privateFS, "/a", "file");
		createDB(sharedFS, "/a", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);

		assertTrue(df.isHijacked());

		df.moveTo(root.getFolder("b"));
		assertEquals("file", df.getName());

		df = root.getFolder("a").getFile("file");
		assertNotNull(df);
	}

	@Test
	public void testCopy() throws IOException, CancelledException {
		createDB(privateFS, "/a", "file");
		createDB(privateFS, "/b", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.copyTo(root.getFolder("b"), null);
		assertEquals("file.1", df.getName());
		assertEquals("/b/file.1", df.getPathname());
		df = root.getFolder("a").getFile("file");
		assertNotNull(df);
	}

	@Test
	public void testCopy1() throws IOException, CancelledException {
		createDB(privateFS, "/a", "file");
		createDB(privateFS, "/b", "file");
		createDB(privateFS, "/b", "file.1");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.copyTo(root.getFolder("b"), null);
		assertEquals("file.2", df.getName());
	}

	@Test
	public void testCopy2() throws IOException, CancelledException {
		createDB(privateFS, "/a", "file");
		createDB(sharedFS, "/b", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.copyTo(root.getFolder("b"), null);
		assertEquals("file.1", df.getName());
	}

	@Test
	public void testCopy3() throws IOException, CancelledException {
		createDB(privateFS, "/a", "file");
		createDB(sharedFS, "/a", "file");
		refresh();

		DomainFile df = root.getFolder("a").getFile("file");
		assertNotNull(df);
		df = df.copyTo(root.getFolder("b"), null);
		assertEquals("file", df.getName());
		assertEquals("/b/file", df.getPathname());

		df = root.getFolder("a").getFile("file");
		assertNotNull(df);
	}

	@Test
	public void testRename() throws IOException, InvalidNameException {
		createDB(privateFS, "/a", "A");
		createDB(privateFS, "/a", "B");
		refresh();

		DomainFile df = root.getFolder("a").getFile("A");
		df = df.setName("C");
		assertEquals("C", df.getName());
		assertEquals("/a/C", df.getPathname());
		assertNull(root.getFolder("a").getFile("A"));
		assertNotNull(root.getFolder("a").getFile("C"));

		try {
			df.setName("B");
			Assert.fail();
		}
		catch (DuplicateFileException e) {

		}
	}

	@Test
	public void testRename2() throws IOException, InvalidNameException {
		createDB(sharedFS, "/a", "A");
		createDB(sharedFS, "/a", "B");
		refresh();

		DomainFile df = root.getFolder("a").getFile("A");
		df = df.setName("C");
		assertEquals("C", df.getName());
		assertEquals("/a/C", df.getPathname());
		assertNull(root.getFolder("a").getFile("A"));
		assertNotNull(root.getFolder("a").getFile("C"));

		try {
			df.setName("B");
			Assert.fail();
		}
		catch (DuplicateFileException e) {

		}
	}

	@Test
	public void testRenameFolder() throws IOException, InvalidNameException {
		createDB(sharedFS, "/a", "A");
		createDB(sharedFS, "/a", "B");
		refresh();

		DomainFolder folder = root.getFolder("a");
		folder.getFiles();// visit folder

		folder = folder.setName("C");
		assertEquals("C", folder.getName());

		DomainFile df = folder.getFile("A");
		assertNotNull(df);
		assertEquals("/C/A", df.getPathname());

		df = folder.getFile("B");
		assertNotNull(df);
		assertEquals("/C/B", df.getPathname());

		assertNull(root.getFolder("a"));

		GhidraFolder dFolder = root.createFolder("D");
		dFolder.getFiles();// visit folder

		folder = folder.moveTo(dFolder);

		df = folder.getFile("A");
		assertNotNull(df);
		assertEquals("/D/C/A", df.getPathname());

		df = folder.getFile("B");
		assertNotNull(df);
		assertEquals("/D/C/B", df.getPathname());

		assertNull(root.getFolder("C"));

	}

	private void createDB(FileSystem fs, String path, String name) throws IOException {
		DBHandle dbh = new DBHandle();
		long checkinId = 0;
		try {
			BufferFile bf = fs.createDatabase(path, name, FileIDFactory.createFileID(), "Test",
				dbh.getBufferSize(), "test", null);
			dbh.saveAs(bf, true, null);
			if (bf instanceof ManagedBufferFile) {
				checkinId = ((ManagedBufferFile) bf).getCheckinID();
			}
			dbh.close();
		}
		catch (IOException e) {
			dbh.close();
			throw e;
		}
		catch (Exception e) {
			e.printStackTrace();
			dbh.close();
			Assert.fail();
		}
		if (fs.isVersioned()) {
			FolderItem item = fs.getItem(path, name);
			assertNotNull(item);
			item.terminateCheckout(checkinId, true);
		}
	}

	private void refresh() throws IOException {
		// refresh everything regardless of visited state
		pfm.refresh(true);
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
