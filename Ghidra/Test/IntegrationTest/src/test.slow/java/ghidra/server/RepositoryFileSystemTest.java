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
package ghidra.server;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import db.*;
import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.store.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.server.store.RepositoryFile;
import ghidra.server.store.RepositoryFolder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.exception.FileInUseException;
import utilities.util.FileUtilities;

public class RepositoryFileSystemTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String USER = ClientUtil.getUserName();

	private File serverRoot;

	private RepositoryManager mgr;
	private Repository repository;

	private List<MyEvent> events = new ArrayList<>();

	@Before
	public void setUp() throws Exception {

		File parent = createTempDirectory(getClass().getSimpleName());

		// Create server instance
		serverRoot = new File(parent, "My_Server");
		FileUtilities.deleteDir(serverRoot);
		serverRoot.mkdir();

		mgr = new RepositoryManager(serverRoot, false, 0, false);
		mgr.getUserManager().addUser(USER);

		repository = mgr.createRepository(USER, "My_Repository");

		LocalFileSystem fs = (LocalFileSystem) getInstanceField("fileSystem", repository);
		fs.addFileSystemListener(new MyFileSystemListener());
	}

	@After
	public void tearDown() throws Exception {
		if (mgr != null) {
			mgr.dispose();
		}
		FileUtilities.deleteDir(serverRoot);
	}

	private RepositoryFile createDatabase(String parentPath, String itemName, int maxVersion)
			throws Exception {

		RepositoryFolder folder = repository.getFolder(USER, parentPath, true);

		DBHandle dbh = new DBHandle();
		long id = dbh.startTransaction();
		Schema schema =
			new Schema(0, "key", new Field[] { IntField.INSTANCE }, new String[] { "dummy" });
		dbh.createTable("test", schema);
		dbh.endTransaction(id, true);
		ManagedBufferFile bf = folder.createDatabase(itemName, FileIDFactory.createFileID(),
			dbh.getBufferSize(), "Database", USER, null);
		bf.setVersionComment("Version 1");
		dbh.saveAs(bf, true, null);
		long checkoutId = bf.getCheckinID();
		assertNotNull(dbh.getTable("test"));
		dbh.close();

		RepositoryFile file = folder.getFile(itemName);
		assertNotNull(file);
		assertEquals(1, file.getItem().getVersion());

		for (int i = 2; i <= maxVersion; i++) {

			// Checkout and open for update
			bf = file.openDatabase(checkoutId, USER);
			dbh = new DBHandle(bf);
			assertTrue(dbh.canUpdate());
			Table testTable = dbh.getTable("test");
			assertEquals(i - 2, testTable.getRecordCount());

			// Verify that update is not permitted for second open
			BufferFile bf2 = file.openDatabase(1, -1, USER);
			DBHandle dbh2 = new DBHandle(bf2);
			assertTrue(!dbh2.canUpdate());
			assertNotNull(dbh2.getTable("test"));
			dbh2.close();

			// Add record
			long txId = dbh.startTransaction();
			DBRecord rec = schema.createRecord(i);
			rec.setIntValue(0, i);
			testTable.putRecord(rec);
			Msg.debug(this, "Added record to test table, key=" + i);
			Msg.debug(this,
				"Added record to Record count for test table: " + testTable.getRecordCount());
			dbh.endTransaction(txId, true);

			// Create new version
			Msg.debug(this, "Saving database version " + i);
			dbh.save("Version " + i, new MyChangeSet(), null);
			dbh.close();

			// Verify item current version
			assertEquals(i, file.getItem().getVersion());

			// Check version history
			Version[] versions = file.getVersions(USER);
			assertEquals(i, versions.length);
			for (int n = 0; n < i; n++) {
				assertEquals(n + 1, versions[n].getVersion());
				assertEquals("Version " + (n + 1), versions[n].getComment());
				assertEquals(USER, versions[n].getUser());
			}

		}
		file.terminateCheckout(checkoutId, USER, false);
		return file;
	}

	@Test
	public void testDeleteDataBaseVersions() {
		try {
			RepositoryFolder rootFolder = repository.getFolder(USER, "/", true);
			RepositoryFolder[] folders = rootFolder.getFolders();
			assertNotNull(folders);
			assertEquals(0, folders.length);

			RepositoryFile file = createDatabase("/abc", "fred", 3);

			RepositoryFolder folder = repository.getFolder(USER, "/abc", false);
			assertNotNull(folder);

			// Can't delete open version
			//		BufferFile bf = item.open((int)1);
			//		try {
			//			item.delete(1);
			//			fail();
			//		} catch (FileInUseException e) {
			//			// expected
			//		}
			//		finally {
			//			bf.close();
			//		}

			// Can't delete checked-out version
			ItemCheckoutStatus coStatus = file.checkout(CheckoutType.NORMAL, USER, null);
			try {
				file.delete(3, USER);
				Assert.fail();
			}
			catch (FileInUseException e) {
				// expected
			}
			file = folder.getFile("fred");
			assertNotNull(file);

			// delete oldest version
			file.delete(1, USER);
			Thread.sleep(50);
			file = folder.getFile("fred");
			assertNotNull(file);

			// verify that version 2 and 3 are still available
			assertEquals(3, file.getItem().getVersion());
			Version[] versions = file.getVersions(USER);
			assertEquals(2, versions.length);
			assertEquals(2, versions[0].getVersion());
			assertEquals(3, versions[1].getVersion());

			file.terminateCheckout(coStatus.getCheckoutId(), USER, false);
			Thread.sleep(50);

			// delete current version
			file.delete(3, USER);
			Thread.sleep(50);
			file = folder.getFile("fred");
			assertNotNull(file);

			// verify that version 2 is still available
			assertEquals(2, file.getItem().getVersion());
			versions = file.getVersions(USER);
			assertEquals(1, versions.length);
			assertEquals(2, versions[0].getVersion());

			// Open version 2 for check
			DBHandle dbh = new DBHandle(file.openDatabase(2, -1, USER));
			try {
				Table testTable = dbh.getTable("test");
				assertEquals(1, testTable.getRecordCount());
				DBRecord rec = testTable.getRecord(2);
				assertNotNull(rec);
				assertEquals(2, rec.getIntValue(0));
			}
			finally {
				dbh.close();
			}

			// delete last version
			file.delete(2, USER);
			Thread.sleep(50);
			file = folder.getFile("fred");
			assertNull(file);

			folders = rootFolder.getFolders();
			assertNotNull(folders);
			assertEquals(0, folders.length);

			Thread.sleep(500);// wait for events

			assertEquals(8, events.size());
			checkEvent("Folder Created", "/", "abc", null, null, events.get(0));
			checkEvent("Item Created", "/abc", "fred", null, null, events.get(1));
			checkEvent("Item Changed", "/abc", "fred", null, null, events.get(2));// version 2 created
			checkEvent("Item Changed", "/abc", "fred", null, null, events.get(3));// version 3 created
			checkEvent("Item Changed", "/abc", "fred", null, null, events.get(4));// version 1 deleted
			checkEvent("Item Changed", "/abc", "fred", null, null, events.get(5));// version 3 deleted
			checkEvent("Item Deleted", "/abc", "fred", null, null, events.get(6));// last version deleted
			checkEvent("Folder Deleted", "/", "abc", null, null, events.get(7));
		}
		catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}
	}

	private void checkEvent(String op, String path, String name, String newPath, String newName,
			Object evObj) {
		MyEvent event = (MyEvent) evObj;
		MyEvent ev = new MyEvent(op, path, name, newPath, newName);
		assertEquals(ev, event);
	}

	class MyChangeSet implements DBChangeSet {

		/*
		 * @see ghidra.framework.model.ChangeSet#read(ghidra.framework.store.db.DBHandle)
		 */
		@Override
		public void read(DBHandle dbh) throws IOException {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#write(ghidra.framework.store.db.DBHandle)
		 */
		@Override
		public void write(DBHandle dbh, boolean isRecoverSave) throws IOException {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#clear()
		 */
		public void clear() {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#undo()
		 */
		public void undo() {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#redo()
		 */
		public void redo() {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#setMaxUndos(int)
		 */
		public void setMaxUndos(int maxUndos) {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#clearUndo()
		 */
		public void clearUndo() {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#startTransaction()
		 */
		public void startTransaction() {
			// TODO Auto-generated method stub

		}

		/*
		 * @see ghidra.framework.model.ChangeSet#endTransaction(boolean)
		 */
		public void endTransaction(boolean commit) {
			// TODO Auto-generated method stub

		}

	}

	class MyFileSystemListener implements FileSystemListener {
		@Override
		public void folderCreated(String parentPath, String name) {
			events.add(new MyEvent("Folder Created", parentPath, name, null, null));
		}

		@Override
		public void itemCreated(String parentPath, String name) {
			events.add(new MyEvent("Item Created", parentPath, name, null, null));
		}

		@Override
		public void folderDeleted(String parentPath, String name) {
			events.add(new MyEvent("Folder Deleted", parentPath, name, null, null));
		}

		@Override
		public void folderMoved(String parentPath, String name, String newParentPath) {
			events.add(new MyEvent("Folder Moved", parentPath, name, newParentPath, null));
		}

		@Override
		public void folderRenamed(String parentPath, String oldFolderName, String newFolderName) {
			events.add(
				new MyEvent("Folder Renamed", parentPath, oldFolderName, null, newFolderName));
		}

		@Override
		public void itemDeleted(String folderPath, String itemName) {
			events.add(new MyEvent("Item Deleted", folderPath, itemName, null, null));
		}

		@Override
		public void itemRenamed(String folderPath, String oldItemName, String newItemName) {
			events.add(new MyEvent("Item Renamed", folderPath, oldItemName, null, newItemName));
		}

		@Override
		public void itemMoved(String parentPath, String name, String newParentPath,
				String newName) {
			events.add(new MyEvent("Item Moved", parentPath, name, newParentPath, newName));
		}

		@Override
		public void itemChanged(String parentPath, String itemName) {
			events.add(new MyEvent("Item Changed", parentPath, itemName, null, null));
		}

		@Override
		public void syncronize() {
			// Nothing to do
		}
	}
}

class MyEvent {
	String op;
	String parentPath;
	String name;
	String newParentPath;
	String newName;

	MyEvent(String op, String parentPath, String name, String newParentPath, String newName) {
		this.op = op;
		this.parentPath = parentPath;
		this.name = name;
		this.newParentPath = newParentPath;
		this.newName = newName;
	}

	@Override
	public boolean equals(Object obj) {
		MyEvent other = (MyEvent) obj;
		return eq(op, other.op) && eq(parentPath, other.parentPath) && eq(name, other.name) &&
			eq(newParentPath, other.newParentPath) && eq(newName, other.newName);
	}

	private boolean eq(String s1, String s2) {
		if (s1 == null) {
			return s2 == null;
		}
		return s1.equals(s2);
	}

	@Override
	public String toString() {
		return op + " " + parentPath + " " + name + " " + newParentPath + " " + newName;
	}
}
