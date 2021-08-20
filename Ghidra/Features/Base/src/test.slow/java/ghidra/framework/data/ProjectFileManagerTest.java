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
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.*;

import generic.test.TestUtils;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FileSystemEventManager;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class ProjectFileManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private File privateProjectDir;
	private File sharedProjectDir;
	private FileSystem sharedFS;
	private LocalFileSystem privateFS;
	private ProjectFileManager fileMgr;
	private DomainFolder root;
	private List<MyEvent> events = new ArrayList<>();

	@Before
	public void setUp() throws Exception {

		LocalFileSystem.setValidationRequired();

		File tempDir = createTempDirectory(getName());
		privateProjectDir = new File(tempDir, "privateFS");
		sharedProjectDir = new File(tempDir, "sharedFS");

		privateProjectDir.delete();
		sharedProjectDir.delete();

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

		fileMgr = new ProjectFileManager(privateFS, sharedFS);
		fileMgr.addDomainFolderChangeListener(new MyDomainFolderChangeListener());
		root = fileMgr.getRootFolder();
		flushFileSystemEventsAndClearTestQueue();
	}

	private void flushFileSystemEventsAndClearTestQueue() {
		flushFileSystemEvents();
		waitForPostedSwingRunnables();
		events.clear();
	}

	@After
	public void tearDown() {
		fileMgr.dispose();
		deleteAll(privateProjectDir);
		deleteAll(sharedProjectDir);
	}

	private void flushFileSystemEvents() {
		FileSystemEventManager privateEventManager =
			(FileSystemEventManager) TestUtils.getInstanceField("eventManager", privateFS);
		FileSystemEventManager sharedEventManager =
			(FileSystemEventManager) TestUtils.getInstanceField("eventManager", sharedFS);

		flushTheseEvents(privateEventManager);
		flushTheseEvents(sharedEventManager);
	}

	private void flushTheseEvents(FileSystemEventManager eventManager) {
		// Events get added synchronously, but processed asynchronously, so we can check to see
		// if any have been added by an action we triggered without waiting.  Also, we know that
		// no more events will get added, since we are the thread (the main thread) doing the 
		// work, so no synchronization is needed for checking the list size.  
		//
		// If there are queued actions, then we have to kick the handling thread and 
		// let it finish running.

		try {
			assertTrue(eventManager.flushEvents(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS));
		}
		catch (InterruptedException e) {
			failWithException("Interrupted waiting for filesystem events", e);
		}
	}

	private void deleteAll(File file) {
		if (file.isDirectory()) {
			File[] files = file.listFiles();
			for (File file2 : files) {
				deleteAll(file2);
			}
		}
		if (!file.delete()) {
			System.err.println("Failed to delete file: " + file);
		}
	}

	@Test
	public void testGetRootFolder() throws Exception {
		DomainFolder rootFolder = fileMgr.getRootFolder();
		assertEquals("/", rootFolder.getPathname());
		assertEquals(3, rootFolder.getFolders().length);
	}

	@Test
	public void testGetFolder() throws Exception {

		DomainFolder rootFolder = fileMgr.getRootFolder();
		DomainFolder df1 = fileMgr.getFolder("/");
		DomainFolder df2 = fileMgr.getFolder("/a");
		DomainFolder df3 = fileMgr.getFolder("/a/y");
		DomainFolder df4 = fileMgr.getFolder("/a/x");

		assertNotNull(rootFolder);
		assertEquals(rootFolder, df1);
		assertEquals("/", df1.getPathname());
		assertEquals(df1, df2.getParent());
		assertEquals("/a", df2.getPathname());
		assertEquals(df2, df3.getParent());
		assertEquals("/a/y", df3.getPathname());
		assertEquals(df2, df4.getParent());
		assertEquals("/a/x", df4.getPathname());

	}

	private DomainFile createFile(DomainFolder folder, String name) throws Exception {
		// Using existing domain object since implementation and content handler is required
		Language language = getSLEIGH_X86_LANGUAGE();
		Program p = new ProgramDB(name, language, language.getDefaultCompilerSpec(), this);
		try {
			return folder.createFile(name, p, TaskMonitor.DUMMY);
		}
		finally {
			p.release(this);
		}
	}

	@Test
	public void testCreateFile() throws Exception {
		DomainFolder folder = fileMgr.getFolder("/a");
		folder.getFiles(); // visit folder to receive change events from this folder
		flushFileSystemEventsAndClearTestQueue();

		DomainFile df1 = createFile(folder, "file1");
		assertNotNull(df1);
		String fileID1 = df1.getFileID();

		assertEventsSize(1);
		checkEvent(events.get(0), "File Added", null, null, "/a/file1", null, null);

		DomainFile df2 = createFile(folder, "file2");
		assertNotNull(df2);
		String fileID2 = df2.getFileID();
		assertEventsSize(2);
		checkEvent(events.get(1), "File Added", null, null, "/a/file2", null, null);

		DomainFile df = fileMgr.getFileByID(fileID1);
		assertNotNull(df);
		assertEquals("file1", df.getName());
		assertTrue(!df.isVersioned());

		df = fileMgr.getFileByID(fileID2);
		assertNotNull(df2);
		assertEquals("file2", df.getName());

		df1.addToVersionControl("", false, TaskMonitor.DUMMY);

		df = fileMgr.getFileByID(fileID1);
		assertNotNull(df1);
		assertEquals("file1", df.getName());
		assertTrue(df.isVersioned());

	}

	@Test
	public void testFileIndex() throws Exception {

		DomainFileIndex fileIndex = (DomainFileIndex) getInstanceField("fileIndex", fileMgr);
		assertNotNull(fileIndex);

		@SuppressWarnings("unchecked")
		HashMap<String, String> fileIdToPathIndex =
			(HashMap<String, String>) getInstanceField("fileIdToPathIndex", fileIndex);
		assertNotNull(fileIdToPathIndex);

		DomainFolder folder = fileMgr.getFolder("/a");

		DomainFile df1 = createFile(folder, "file1");
		String fileID = df1.getFileID();

		assertEquals(df1, fileMgr.getFileByID(fileID));

		// invalidate folder data to force search

		GhidraFolderData rootFolderData = fileMgr.getRootFolderData();
		rootFolderData.dispose();

		assertTrue(fileIdToPathIndex.isEmpty()); // folder invalidation should cause map to clear

		assertEquals(df1, fileMgr.getFileByID(fileID));

		assertFalse(fileIdToPathIndex.isEmpty()); // index should become populated
	}

	@Test
	public void testFileIndexUndoCheckout() throws Exception {
// TODO: This only tests the connected state - a remote file-system is required to test the disconnect/re-connected condition
		DomainFolder folder = fileMgr.getFolder("/a");

		DomainFile df1 = createFile(folder, "file1");
		String fileID = df1.getFileID();

		df1.addToVersionControl("", true, TaskMonitor.DUMMY);
		assertEquals(fileID, df1.getFileID());

		df1.undoCheckout(true);
		DomainFile keepDf = folder.getFile("file1.keep");
		assertNotNull(keepDf);
		String newFileID = keepDf.getFileID();
		assertNotNull(newFileID);
		assertTrue(!fileID.equals(newFileID));
	}

	@Test
	public void testFileIndexHijack() throws Exception {
// TODO: This only tests the connected state - a remote file-system is required to test the disconnect/re-connected condition
		DomainFolder folder = fileMgr.getFolder("/a");
		folder.getFiles(); // visit folder to enable folder change listener

		// create shared file /a/file1 and keep checked-out
		DomainFile df1 = createFile(folder, "file1");
		String fileID = df1.getFileID();
		df1.addToVersionControl("", true, TaskMonitor.DUMMY);
		assertEquals(fileID, df1.getFileID());

		// Force Hijack - terminate checkout at versioned file-system
		long checkoutId = privateFS.getItem("/a", "file1").getCheckoutId();
		sharedFS.getItem("/a", "file1").terminateCheckout(checkoutId, true);

		flushFileSystemEvents();

		assertTrue(df1.isHijacked());
		assertEquals(fileID, df1.getFileID());

		df1.setName("file2");

		DomainFile df2 = fileMgr.getFile("/a/file2");

		assertTrue(!fileID.equals(df2.getFileID()));

	}

	@Test
	public void testFolderCreatedEvent() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it
		flushFileSystemEventsAndClearTestQueue();

		sharedFS.createFolder("/", "abc");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(4, root.getFolders().length);
		assertEventsSize(1);
		checkEvent(events.get(0), "Folder Added", null, "/abc", null, null, null);

		sharedFS.createFolder("/", "xyz");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(5, root.getFolders().length);

		DomainFolder abcFolder = root.getFolder("abc");
		abcFolder.getFolders(); // visit folder to receive change events for it

		sharedFS.createFolder("/abc", "subfolder");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(1, abcFolder.getFolders().length);

		DomainFolder subFolder = abcFolder.getFolder("subfolder");
		sharedFS.createFolder("/abc/subfolder", "sub2folder");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(1, subFolder.getFolders().length);
	}

	@Test
	public void testFolderCreatedEvent2() throws Exception {
		DomainFolder aFolder = root.getFolder("a");

		sharedFS.createFolder("/a", "s");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, aFolder.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		// exists in localFS so "b" should not get created
		sharedFS.createFolder("/", "b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);
		assertEventsSize(0);

		sharedFS.createFolder("/b", "subB");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		DomainFolder bFolder = root.getFolder("b");
		assertEquals(1, bFolder.getFolders().length);
	}

	@Test
	public void testFolderDeletedEvent4() throws Exception {
		sharedFS.deleteFolder("/a/y");
		sharedFS.deleteFolder("/a");
		GhidraFolder folder = (GhidraFolder) root.getFolder("a");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertTrue(!folder.sharedExists());
		assertTrue(folder.privateExists());
		folder = folder.getFolder("x");
		assertTrue(!folder.sharedExists());
		assertTrue(folder.privateExists());
	}

	@Test
	public void testFolderDeletedEvent() throws Exception {
		sharedFS.createFolder("/", "abc");
		sharedFS.createFolder("/", "xyz");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(5, root.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		sharedFS.deleteFolder("/abc");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(4, root.getFolders().length);

		assertEventsSize(1);
		checkEvent(events.get(0), "Folder Removed", "/", null, null, null, "abc");
	}

	@Test
	public void testFolderDeletedEvent2() throws Exception {
		sharedFS.createFolder("/", "abc");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		DomainFolder abcFolder = root.getFolder("abc");
		sharedFS.createFolder("/abc", "subfolder");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(1, abcFolder.getFolders().length);

		sharedFS.deleteFolder("/abc/subfolder");
		assertTrue(!sharedFS.folderExists("/abc/subfolder"));
		assertTrue(sharedFS.folderExists("/abc"));
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder

		sharedFS.deleteFolder("/abc");
		assertTrue(!sharedFS.folderExists("/abc/subfolder"));
		assertTrue(!sharedFS.folderExists("/abc"));
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder

		assertNull(root.getFolder("abc"));
	}

	@Test
	public void testFolderDeleted3() throws Exception {
		// exists in localFS so "b" folder should not get created again
		sharedFS.createFolder("/", "b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		// delete "b"; should remain because "b" exists on local FS
		sharedFS.deleteFolder("/b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder

		assertEventsSize(0);
		assertEquals(3, root.getFolders().length);
		assertNotNull(root.getFolder("b"));
	}

	@Test
	public void testFolderRenamedEvent() throws Exception {
		sharedFS.createFolder("/", "abc");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(4, root.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		sharedFS.renameFolder("/", "abc", "xyz");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder		
		assertEquals(4, root.getFolders().length);

		assertEventsSize(2);
		checkEvent(events.get(0), "Folder Removed", "/", null, null, null, "abc");
		checkEvent(events.get(1), "Folder Added", null, "/xyz", null, null, null);

		assertNull(root.getFolder("abc"));
		assertNotNull(root.getFolder("xyz"));
	}

	@Test
	public void testFolderRenamedEvent2() throws Exception {
		// exists in localFS so "b" folder should not get created again
		sharedFS.createFolder("/", "b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);
		DomainFolder bFolder = root.getFolder("b");
		bFolder.setName("bigB");
		try {
			sharedFS.renameFolder("/", "b", "bigB");
			Assert.fail("Should not have found a 'b' folder!");
		}
		catch (IOException e) {
			// expected
		}

		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);

		assertNotNull(root.getFolder("bigB"));
	}

	@Test
	public void testFolderRenamedEvent3() throws Exception {
		fileMgr.getFolder("/a"); // force folder refresh to reduce event count
		flushFileSystemEventsAndClearTestQueue();

		// exists in localFS so "b" folder should not get created again
		sharedFS.createFolder("/", "b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		sharedFS.renameFolder("/", "b", "bigB");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(4, root.getFolders().length);

		assertEventsSize(1);
		checkEvent(events.get(0), "Folder Added", null, "/bigB", null, null, null);

		assertNotNull(root.getFolder("bigB"));
		assertNotNull(root.getFolder("b"));
	}

	@Test
	public void testRenameFolder5() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it
		sharedFS.renameFolder("/", "a", "bigA");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEventsSize(1);

		checkEvent(events.get(0), "Folder Added", null, "/bigA", null, null, null);

		// versioned folder was renamed to /bigA, but private folder /a should still exist

		GhidraFolder folder = (GhidraFolder) root.getFolder("a");
		assertNotNull(folder);
		assertTrue(folder.privateExists());
		assertFalse(folder.sharedExists());

		folder = (GhidraFolder) root.getFolder("bigA");
		assertNotNull(folder);
		assertFalse(folder.privateExists());
		assertTrue(folder.sharedExists());
	}

	@Test
	public void testRenameFolder6() throws Exception {
		DomainFolder aFolder = fileMgr.getFolder("/a");
		assertNotNull(aFolder);
		aFolder.getFolders(); // visit folder to receive change events for it

		sharedFS.renameFolder("/a", "y", "bigY");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder

		assertEventsSize(2);
		checkEvent(events.get(0), "Folder Removed", "/a", null, null, null, "y");
		checkEvent(events.get(1), "Folder Added", null, "/a/bigY", null, null, null);

	}

	@Test
	public void testRenameFolder7() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it
		sharedFS.renameFolder("/", "c", "bigC");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertNull(root.getFolder("c"));
		assertNotNull(root.getFolder("bigC"));

		assertEventsSize(2);
		checkEvent(events.get(0), "Folder Removed", "/", null, null, null, "c");
		checkEvent(events.get(1), "Folder Added", null, "/bigC", null, null, null);
	}

	@Test
	public void testFolderMovedEvent() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it

		sharedFS.createFolder("/", "abc");
		sharedFS.createFolder("/", "xyz");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(5, root.getFolders().length);

		DomainFolder xyzFolder = root.getFolder("xyz");
		xyzFolder.getFolders(); // visit folder to receive change events for it

		flushFileSystemEventsAndClearTestQueue();
		sharedFS.moveFolder("/", "abc", "/xyz");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(4, root.getFolders().length);
		assertNull(root.getFolder("abc"));
		assertEventsSize(2);
		checkEvent(events.get(0), "Folder Removed", "/", null, null, null, "abc");
		checkEvent(events.get(1), "Folder Added", null, "/xyz/abc", null, null, null);

		assertEquals(1, xyzFolder.getFolders().length);
		DomainFolder abcFolder = xyzFolder.getFolder("abc");
		assertEquals("/xyz/abc", abcFolder.getPathname());
	}

	@Test
	public void testFolderMovedEvent2() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it

		DomainFolder aFolder = root.getFolder("a");
		aFolder.getFolders(); // visit folder to receive change events for it

		// exists in localFS so "b" folder should not get created again
		sharedFS.createFolder("/", "b");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);

		flushFileSystemEventsAndClearTestQueue();
		sharedFS.moveFolder("/", "b", "/a");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);
		assertEventsSize(1);
		checkEvent(events.get(0), "Folder Added", null, "/a/b", null, null, null);
	}

	@Test
	public void testFolderMovedEvent3() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it

		DomainFolder aFolder = root.getFolder("a");
		aFolder.getFolders(); // visit folder to receive change events for it

		// "c" exists in sharedFS so "c" folder should not get created again
		root.createFolder("c");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);

		sharedFS.moveFolder("/", "c", "/a");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEquals(3, root.getFolders().length);
		assertTrue(sharedFS.folderExists("/a/c"));
		assertTrue(!privateFS.folderExists("/a/c"));
	}

	@Test
	public void testFolderMovedEvent4() throws Exception {
		root.getFolders(); // visit root folder to receive change events for it

		DomainFolder cFolder = root.getFolder("c");
		cFolder.getFolders(); // visit folder to receive change events for it

		sharedFS.moveFolder("/", "a", "/c");
		flushFileSystemEvents(); // wait for FileSystemListener callback to update folder
		assertEventsSize(1);

		checkEvent(events.get(0), "Folder Added", null, "/c/a", null, null, null);

		// versioned folder was moved to /c/a, but private folder /a should still exist

		GhidraFolder folder = (GhidraFolder) fileMgr.getFolder("/a");
		assertNotNull(folder);
		assertTrue(folder.privateExists());
		assertFalse(folder.sharedExists());

		folder = (GhidraFolder) fileMgr.getFolder("/c/a");
		assertNotNull(folder);
		assertFalse(folder.privateExists());
		assertTrue(folder.sharedExists());
	}

	private void checkEvent(Object evObj, String op, String parent, String folder, String file,
			String oldParent, String name) {
		MyEvent event = (MyEvent) evObj;
		MyEvent ev = new MyEvent(op, parent, folder, file, oldParent, name);
		assertEquals(ev, event);
	}

	private void assertEventsSize(int size) {
		waitForPostedSwingRunnables();
		int eventCount = events.size();
		if (eventCount == size) {
			return; // all is well
		}

		// need to print an error and then fail
		Logger rootLogger = LogManager.getRootLogger();
		rootLogger.error("Expected " + size + " events and found: " + eventCount);
		for (MyEvent event : events) {
			rootLogger.error("\tevent: " + event);
		}

		Assert.fail(
			"Expected " + size + " events and found: " + eventCount + "(see log for details)");
	}

	class MyDomainFolderChangeListener implements DomainFolderChangeListener {

		@Override
		public void domainFolderAdded(DomainFolder folder) {
			events.add(new MyEvent("Folder Added", null, folder.getPathname(), null, null, null));
		}

		@Override
		public void domainFileAdded(DomainFile file) {
			events.add(new MyEvent("File Added", null, null, file.getPathname(), null, null));
		}

		@Override
		public void domainFolderRemoved(DomainFolder parent, String name) {
			events.add(new MyEvent("Folder Removed", parent.getPathname(), null, null, null, name));
		}

		@Override
		public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
			events.add(new MyEvent("FileRemoved", parent.getPathname(), null, null, null, name));
		}

		@Override
		public void domainFolderRenamed(DomainFolder folder, String oldName) {
			events.add(
				new MyEvent("Folder Renamed", null, folder.getPathname(), null, null, oldName));
		}

		@Override
		public void domainFileRenamed(DomainFile file, String oldName) {
			events.add(new MyEvent("File Renamed", null, null, file.getPathname(), null, oldName));
		}

		@Override
		public void domainFolderSetActive(DomainFolder folder) {
			events.add(
				new MyEvent("Folder SetActive", null, folder.getPathname(), null, null, null));
		}

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			events.add(
				new MyEvent("File StatusChanged", null, null, file.getPathname(), null, null));
		}

		@Override
		public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
			events.add(new MyEvent("Folder Moved", null, folder.getPathname(), null,
				oldParent.getPathname(), null));
		}

		@Override
		public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
			events.add(new MyEvent("File Moved", null, null, file.getPathname(),
				oldParent.getPathname(), oldName));
		}

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
			// not tested
		}

		@Override
		public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
			// not tested
		}

		@Override
		public void domainFileObjectClosed(DomainFile file, DomainObject object) {
			// not tested
		}
	}
}

class MyEvent {
	String op;
	String folder;
	String parent;
	String oldParent;
	String file;
	String name;

	MyEvent(String op, String parent, String folder, String file, String oldParent, String name) {
		this.op = op;
		this.parent = parent;
		this.folder = folder;
		this.file = file;
		this.oldParent = oldParent;
		this.name = name;
	}

	@Override
	public boolean equals(Object obj) {
		MyEvent other = (MyEvent) obj;
		return eq(op, other.op) && eq(folder, other.folder) && eq(name, other.name) &&
			eq(parent, other.parent) && eq(oldParent, other.oldParent) && eq(file, other.file);
	}

	@Override
	public int hashCode() {
		return op.hashCode();
	}

	private boolean eq(Object s1, Object s2) {
		if (s1 == null) {
			return s2 == null;
		}
		return s1.equals(s2);
	}

	@Override
	public String toString() {
		return op + " " + parent + " " + folder + " " + file + " " + oldParent + " " + name;
	}
}
