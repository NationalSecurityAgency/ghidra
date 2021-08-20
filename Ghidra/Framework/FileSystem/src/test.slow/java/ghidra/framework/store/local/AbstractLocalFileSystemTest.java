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
package ghidra.framework.store.local;

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.*;

import db.*;
import db.buffers.BufferFile;
import generic.test.*;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.PropertyFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public abstract class AbstractLocalFileSystemTest extends AbstractGenericTest {

	boolean useIndexedFileSystem;
	LocalFileSystem fs;
	File projectDir;

	List<MyEvent> events = new ArrayList<>();

	public AbstractLocalFileSystemTest(boolean useIndexedFileSystem) {
		super();
		this.useIndexedFileSystem = useIndexedFileSystem;
	}

	@Before
	public void setUp() throws Exception {

		File tempDir = new File(AbstractGTest.getTestDirectoryPath());
		projectDir = new File(tempDir, "testproject");
		FileUtilities.deleteDir(projectDir);
		projectDir.mkdir();

		System.out.println(projectDir.getAbsolutePath());

		fs = LocalFileSystem.getLocalFileSystem(projectDir.getAbsolutePath(), useIndexedFileSystem,
			false, false, true);

		fs.createFolder("/", "a");
		fs.createFolder("/a", "x");
		fs.createFolder("/", "b");
		fs.createFolder("/", "c");
		fs.createFolder("/", "B");
		fs.createFolder("/", "~B");
		fs.createFolder("/~B", "~C");

		// Hidden dir should been unseen by tests
		File hiddenDir = new File(projectDir, LocalFileSystem.HIDDEN_DIR_PREFIX + "admin");
		hiddenDir.mkdir();

		// Misc file in root should be unseen by tests
		File miscFile = new File(projectDir, "misc");
		OutputStream out = new FileOutputStream(miscFile);
		out.close();

		// WARNING! Asynchronous event dispatching can result in timing issues when
		// verifying dispatched events collected
		fs.addFileSystemListener(new MyFileSystemListener());
	}

	@After
	public void tearDown() {
		if (fs != null) {
			fs.dispose();
		}
		FileUtilities.deleteDir(projectDir);
	}

	@Test
	public void testGetFolders() throws IOException {
		String[] folderNames = fs.getFolderNames("/");
		assertEquals(5, folderNames.length);
		assertEquals("B", folderNames[0]);
		assertEquals("a", folderNames[1]);
		assertEquals("b", folderNames[2]);
		assertEquals("c", folderNames[3]);
		assertEquals("~B", folderNames[4]);

		folderNames = fs.getFolderNames("/a");
		assertEquals(1, folderNames.length);
		assertEquals("x", folderNames[0]);

		folderNames = fs.getFolderNames("/~B");
		assertEquals(1, folderNames.length);
		assertEquals("~C", folderNames[0]);

		try {
			fs.getFolderNames("a");
			Assert.fail();
		}
		catch (IOException e) {
			// expected
		}

		try {
			fs.getFolderNames("/g");
			Assert.fail();
		}
		catch (IOException e) {
			// expected
		}

	}

	@Test
	public void testCreateFolder() throws Exception {
		fs.createFolder("/", "abc");
		flushFileSystemEvents();
		assertEquals(6, fs.getFolderNames("/").length);
		assertEquals(1, events.size());
		checkEvent("Folder Created", "/", "abc", null, null, events.get(0));

		flushFileSystemEvents();
		events.clear();

		// Create existing folder has no affect
		assertTrue(fs.folderExists("/abc"));
		fs.createFolder("/", "abc");
		assertTrue(fs.folderExists("/abc"));

		flushFileSystemEvents();
		assertEquals(0, events.size());

		fs.createFolder("/abc", "def");
		assertEquals("def", fs.getFolderNames("/abc")[0]);
		fs.createFolder("/aaa", "bbb");

		fs.createFolder("/aaa", "b^c");

		flushFileSystemEvents();
		events.clear();

		fs.createFolder("/a1/a2/a3", "a4");

		flushFileSystemEvents();
		assertEquals(4, events.size());
		checkEvent("Folder Created", "/", "a1", null, null, events.get(0));
		checkEvent("Folder Created", "/a1/a2/a3", "a4", null, null, events.get(3));
	}

	private void checkEvent(String op, String path, String name, String newPath, String newName,
			Object evObj) {
		MyEvent event = (MyEvent) evObj;
		MyEvent ev = new MyEvent(op, path, name, newPath, newName);
		assertEquals(ev, event);
	}

	@Test
	public void testDeleteFolder() throws Exception {
		fs.createFolder("/abc/def", "ghi");
		flushFileSystemEvents();
		assertEquals(1, fs.getFolderNames("/abc/def").length);
		flushFileSystemEvents();
		events.clear();
		fs.deleteFolder("/abc/def/ghi");
		flushFileSystemEvents();
		assertEquals(0, fs.getFolderNames("/abc/def").length);
		assertEquals(1, fs.getFolderNames("/abc").length);
		assertEquals(1, events.size());
		checkEvent("Folder Deleted", "/abc/def", "ghi", null, null, events.get(0));

		fs.createFolder("/abc/def", "ghi");
		flushFileSystemEvents();
		assertEquals(1, fs.getFolderNames("/abc/def").length);
		try {
			fs.deleteFolder("/abc/def");
			Assert.fail();
		}
		catch (FolderNotEmptyException e) {
			// expected
		}
	}

	@Test
	public void testRenameFolder() throws Exception {
		fs.createFolder("/abc/def", "ghi");
		flushFileSystemEvents();
		events.clear();
		fs.renameFolder("/abc", "def", "xyz");
		flushFileSystemEvents();
		assertEquals(1, fs.getFolderNames("/abc/xyz").length);
		assertTrue(fs.folderExists("/abc/xyz/ghi"));
		assertEquals(1, events.size());
		checkEvent("Folder Renamed", "/abc", "def", null, "xyz", events.get(0));
	}

	@Test
	public void testRenameFile() throws Exception {
		testCreateDataBase();
		events.clear();

		LocalDatabaseItem item = (LocalDatabaseItem) fs.getItem("/abc", "wilma");
		File dataDir = item.getDataDir();
		assertTrue(dataDir.isDirectory());

		// Rename and refresh item
		fs.moveItem("/abc", "wilma", "/abc", "barney");
		item = (LocalDatabaseItem) fs.getItem("/abc", "barney");
		flushFileSystemEvents();

		assertEquals(1, events.size());
		checkEvent("Item Renamed", "/abc", "wilma", null, "barney", events.get(0));
		events.clear();

		dataDir = item.getDataDir();
		assertEquals("barney", item.getName());
		assertEquals("/abc/barney", item.getPathName());

		// Get storage name based upon data dir name ~<storage-name>.db
		String storageName = dataDir.getName();
		storageName = storageName.substring(0,
			storageName.length() - LocalFolderItem.DATA_DIR_EXTENSION.length()).substring(1);
		File propertyFile =
			new File(dataDir.getParentFile(), storageName + PropertyFile.PROPERTY_EXT);
		assertTrue(propertyFile.isFile());

		item.delete(-1, "test");

		flushFileSystemEvents();

		assertEquals(1, events.size());
		checkEvent("Item Deleted", "/abc", "barney", null, null, events.get(0));

		assertNull(fs.getItem("/abc", "barney"));
	}

	@Test
	public void testMoveFolder() throws Exception {
		fs.createFolder("/abc/def", "ghi");
		flushFileSystemEvents();
		events.clear();
		fs.moveFolder("/abc/def", "ghi", "/abc/xyz");
		assertEquals("ghi", fs.getFolderNames("/abc/xyz")[0]);
		flushFileSystemEvents();
		assertEquals(2, events.size());
		checkEvent("Folder Created", "/abc", "xyz", null, null, events.get(0));
		checkEvent("Folder Moved", "/abc/def", "ghi", "/abc/xyz", null, events.get(1));

		fs.moveFolder("/", "abc", "/mno");
		assertEquals("ghi", fs.getFolderNames("/mno/abc/xyz")[0]);
		try {
			fs.moveFolder("/abc", "def", "/zzz");
			Assert.fail();
		}
		catch (FileNotFoundException e) {
			// expected
		}
		fs.createFolder("/b", "def");
		try {
			fs.moveFolder("/mno/abc", "def", "/b");
		}
		catch (DuplicateFileException e) {
			// expected
		}
	}

	@Test
	public void testCreateDataFile() throws Exception {
		fs.createFolder("/", "abc");
		String data = "This is a test";
		byte[] dataBytes = data.getBytes();
		DataFileItem df = fs.createDataFile("/abc", "fred", new ByteArrayInputStream(dataBytes),
			null, "Data", null);
		InputStream is = df.getInputStream();
		byte[] buffer = new byte[1024];
		int n = is.read(buffer);
		is.close();
		assertEquals(dataBytes.length, n);
		String s = new String(buffer, 0, n);
		assertEquals(data, s);
		flushFileSystemEvents();
		assertEquals(2, events.size());
		checkEvent("Item Created", "/abc", "fred", null, null, events.get(1));

	}

	@Test
	public void testFileNames() throws Exception {

		String data = "This is a test";
		byte[] dataBytes = data.getBytes();

		try {
			createItem(dataBytes, "/", LocalFileSystem.HIDDEN_ITEM_PREFIX + "test");
			Assert.fail("InvalidNameException expected");
		}
		catch (InvalidNameException e) {
			// expected
		}

		for (char cstart = 20; cstart < 255; cstart += fs.getMaxNameLength()) {

			String name = makeName(cstart, fs.getMaxNameLength());

			DataFileItem df = createItem(dataBytes, "/", name);

			FolderItem fi = fs.getItem("/", name);
			assertNotNull(fi);
			assertEquals(name, fi.getName());

			InputStream is = df.getInputStream();
			byte[] buffer = new byte[1024];
			int n = is.read(buffer);
			is.close();
			assertEquals(dataBytes.length, n);
			String s = new String(buffer, 0, n);
			assertEquals(data, s);

			flushFileSystemEvents();
			events.clear();
		}

	}

	@Test
	public void testReopenFileNames() throws Exception {

		testFileNames();

		String data = "This is a test";
		byte[] dataBytes = data.getBytes();

		List<String> names = new ArrayList<>();
		for (String itemName : fs.getItemNames("/")) {
			names.add(itemName);
		}

		fs.dispose();
		fs = LocalFileSystem.getLocalFileSystem(projectDir.getAbsolutePath(), false, false, false,
			true);

		for (String name : names) {

			DataFileItem df = (DataFileItem) fs.getItem("/", name);
			assertNotNull(df);
			assertEquals(name, df.getName());

			InputStream is = new ByteArrayInputStream(dataBytes);
			is = df.getInputStream();
			byte[] buffer = new byte[1024];
			int n = is.read(buffer);
			is.close();
			assertEquals(dataBytes.length, n);
			String s = new String(buffer, 0, n);
			assertEquals(data, s);

		}

	}

	private DataFileItem createItem(byte[] dataBytes, String folderPath, String name)
			throws InvalidNameException, CancelledException, IOException {
		InputStream is = new ByteArrayInputStream(dataBytes);

		DataFileItem df = fs.createDataFile(folderPath, name, is, null, "Data", null);
		assertNotNull(df);
		is.close();

		FolderItem item = fs.getItem(folderPath, name);
		assertNotNull(item);
		assertEquals(name, item.getName());
		assertEquals(folderPath, item.getParentPath());
		assertEquals(LocalFileSystem.getPath(folderPath, name), item.getPathName());

		return df;
	}

	@Test
	public void testFilePaths() throws Exception {

		String data = "This is a test";
		byte[] dataBytes = data.getBytes();

		fs.createFolder("/", "aaa");

		createItem(dataBytes, "/aaa", "~)(%$#@!JGJ");

		for (char cstart = 20; cstart < 255; cstart += fs.getMaxNameLength()) {
			String name = makeName(cstart, fs.getMaxNameLength());
			createItem(dataBytes, "/aaa", name);
			flushFileSystemEvents();
			events.clear();
		}

		fs.moveFolder("/", "aaa", "/a/x");

		fs.renameFolder("/a/x", "aaa", "bbb");

		for (String itemName : fs.getItemNames("/a/x/bbb", true)) {

			FolderItem item = fs.getItem("/a/x/bbb", itemName);
			assertNotNull(item);
			assertEquals(itemName, item.getName());
			assertEquals("/a/x/bbb", item.getParentPath());
			assertEquals("/a/x/bbb/" + itemName, item.getPathName());
		}

	}

	@Test
	public void testFilePathsWithSpaces() throws Exception {

		String data = "This is a test";
		byte[] dataBytes = data.getBytes();

		fs.createFolder("/", "a a a ");
		fs.createFolder("/", "b b b ");

		createItem(dataBytes, "/a a a ", "~)(%$#@!JG J ");

		for (char cstart = 20; cstart < 255; cstart += fs.getMaxNameLength()) {
			String name = makeName(cstart, fs.getMaxNameLength());
			createItem(dataBytes, "/a a a /b b b ", name);
			flushFileSystemEvents();
			events.clear();
		}

		fs.moveFolder("/", "a a a ", "/a/x");

		fs.renameFolder("/a/x", "a a a ", "bbb");

		// close and re-open filesystem (re-read index)
		fs.dispose();
		fs = LocalFileSystem.getLocalFileSystem(projectDir.getAbsolutePath(), false, false, false,
			true);

		for (String itemName : fs.getItemNames("/a/x/bbb/b b b ", true)) {

			FolderItem item = fs.getItem("/a/x/bbb/b b b ", itemName);
			assertNotNull(item);
			assertEquals(itemName, item.getName());
			assertEquals("/a/x/bbb/b b b ", item.getParentPath());
			assertEquals("/a/x/bbb/b b b /" + itemName, item.getPathName());
		}

	}

	protected String makeName(char startChar, int count) {
		char[] chars = new char[count];
		for (int i = 0; i < count; i++) {
			char c = (char) (startChar + i);
			if (!LocalFileSystem.isValidNameCharacter(c)) {
				c = 'x';
			}
			chars[i] = c;
		}
		return new String(chars);
	}

	@Test
	public void testCreateDataBase() throws Exception {

		createDatabase("/abc", "fred", "123");
//		fs.createFolder("/", "abc");
//		DBHandle dbh = new DBHandle();
//		long id = dbh.startTransaction();
//		dbh.createTable("test",
//			new Schema(0, "key", new Class[] { IntField.class }, new String[] { "dummy" }));
//		dbh.endTransaction(id, true);
//		BufferFile bf =
//			fs.createDatabase("/abc", "fred", null, "Database", dbh.getBufferSize(), "bob", null);
//		dbh.saveAs(bf, true, null);
//		assertNotNull(dbh.getTable("test"));
//		dbh.close();

		DatabaseItem item = (DatabaseItem) fs.getItem("/abc", "fred");
		assertNotNull(item);
		BufferFile bf = item.openForUpdate(-1);
		DBHandle dbh = new DBHandle(bf);
		assertTrue(dbh.canUpdate());
		assertNotNull(dbh.getTable("test"));

		BufferFile bf2 = item.open();
		DBHandle dbh2 = new DBHandle(bf2);
		assertTrue(!dbh2.canUpdate());
		assertNotNull(dbh2.getTable("test"));
		dbh2.close();

		dbh.close();

		bf2 = item.open();
		assertNotNull(bf2);
		bf2.close();

		flushFileSystemEvents();
		assertEquals(2, events.size());
		checkEvent("Item Created", "/abc", "fred", null, null, events.get(1));
		events.clear();

		fs.moveItem("/abc", "fred", "/abc", "wilma");
		DatabaseItem item2 = (DatabaseItem) fs.getItem("/abc", "wilma");
		assertNotNull(item2);

		bf2 = item2.open();
		assertNotNull(bf2);
		bf2.close();

		flushFileSystemEvents();
		assertEquals(1, events.size());
		checkEvent("Item Renamed", "/abc", "fred", null, "wilma", events.get(0));

	}

	@Test
	public void testCreateTemporaryDatabase() throws Exception {

		fs.createFolder("/", "abc");
		DBHandle dbh = new DBHandle();
		long id = dbh.startTransaction();
		dbh.createTable("test",
			new Schema(0, "key", new Field[] { IntField.INSTANCE }, new String[] { "dummy" }));
		dbh.endTransaction(id, true);
		BufferFile bf =
			fs.createDatabase("/abc", "fred", null, "Database", dbh.getBufferSize(), "bob", null);
		dbh.saveAs(bf, true, null);
		assertNotNull(dbh.getTable("test"));
		dbh.close();

		DatabaseItem item = (DatabaseItem) fs.getItem("/abc", "fred");
		assertNotNull(item);

		LocalDatabaseItem tmpItem;
		BufferFile bufferFile = item.open();
		try {
			tmpItem = fs.createTemporaryDatabase("/abc", "fred.tmp", item.getFileID(), bufferFile,
				item.getContentType(), false, null);
		}
		finally {
			bufferFile.dispose();
		}
		assertEquals(item.getFileID(), tmpItem.getFileID());

		String[] names = fs.getItemNames("/abc");
		assertEquals(1, names.length);
		assertEquals("fred", names[0]);

		names = fs.getItemNames("/abc", true);
		assertEquals(2, names.length);
		assertEquals("fred", names[1]);
		assertEquals(LocalFileSystem.HIDDEN_ITEM_PREFIX + "fred.tmp", names[0]);

		tmpItem.delete(-1, "test");

		names = fs.getItemNames("/abc", true);
		assertEquals(1, names.length);
		assertEquals("fred", names[0]);
	}

	@Test
	public void testDeleteItem() throws Exception {

		testCreateDataBase();

		flushFileSystemEvents();
		events.clear();

		LocalDatabaseItem item = (LocalDatabaseItem) fs.getItem("/abc", "wilma");
		File dataDir = item.getDataDir();
		assertTrue(dataDir.isDirectory());

		// Get storage name based upon data dir name ~<storage-name>.db
		String storageName = dataDir.getName();
		storageName = storageName.substring(0,
			storageName.length() - LocalFolderItem.DATA_DIR_EXTENSION.length()).substring(1);
		File propertyFile =
			new File(dataDir.getParentFile(), storageName + PropertyFile.PROPERTY_EXT);
		assertTrue(propertyFile.isFile());

		item.delete(-1, "test");

		flushFileSystemEvents();

		assertEquals(1, events.size());
		checkEvent("Item Deleted", "/abc", "wilma", null, null, events.get(0));

		assertNull(fs.getItem("/abc", "wilma"));
	}

	public void testGetItems() throws Exception {
		fs.createFolder("/", "abc");
		String data = "This is a test";
		byte[] dataBytes = data.getBytes();

		DataFileItem df = fs.createDataFile("/abc", "fred", new ByteArrayInputStream(dataBytes),
			null, "Data", null);
		createDatabase("/abc", "greg", "123");

		String[] items = fs.getItemNames("/abc");
		assertEquals(3, items.length);
		assertEquals("bob", items[0]);
		assertEquals("fred", items[1]);
		assertEquals("greg", items[2]);

		assertEquals(LocalDataFile.class, fs.getItem("/abc", items[0]).getClass());
		assertEquals(LocalDataFile.class, fs.getItem("/abc", items[1]).getClass());
		assertEquals(LocalDatabaseItem.class, fs.getItem("/abc", items[2]).getClass());

		df = (DataFileItem) fs.getItem("/abc", items[0]);
		InputStream is = df.getInputStream();
		byte[] buffer = new byte[1024];
		int n = is.read(buffer);
		is.close();
		assertEquals(dataBytes.length, n);
		String s = new String(buffer, 0, n);
		assertEquals(data, s);

		DatabaseItem db = (DatabaseItem) fs.getItem("/abc", items[2]);
		BufferFile bf = db.open(-1);
		DBHandle dbh = new DBHandle(bf);
		assertNotNull(dbh.getTable("test"));
		dbh.close();

	}

	@Test
	public void testMoveDataFile() throws Exception {
		fs.createFolder("/", "abc");
		fs.createDataFile("/abc", "fred", null, null, "Data", null);
		flushFileSystemEvents();
		events.clear();

		FolderItem item = fs.getItem("/abc", "fred");
		assertNotNull(item);

		fs.moveItem("/abc", "fred", "/xyz", "bob");

		assertNull(fs.getItem("/abc", "fred"));
		LocalDataFile df = (LocalDataFile) fs.getItem("/xyz", "bob");
		assertNotNull(df);

		try (InputStream in = df.getInputStream()) {
			// expected success
		}
		catch (IOException e) {
			fail("failed to open data file");
		}

		flushFileSystemEvents();
		assertEquals(2, events.size());
		checkEvent("Folder Created", "/", "xyz", null, null, events.get(0));
		checkEvent("Item Moved", "/abc", "fred", "/xyz", "bob", events.get(1));
	}

	@Test
	public void testMoveDatabase() throws Exception {
		fs.createFolder("/", "abc");
		DBHandle dbh = new DBHandle();
		long id = dbh.startTransaction();
		dbh.createTable("test",
			new Schema(0, "key", new Field[] { IntField.INSTANCE }, new String[] { "dummy" }));
		dbh.endTransaction(id, true);
		BufferFile bf =
			fs.createDatabase("/abc", "greg", "123", "Database", dbh.getBufferSize(), "test", null);
		dbh.saveAs(bf, true, TaskMonitor.DUMMY);
		dbh.close();

		FolderItem item = fs.getItem("/abc", "greg");
		assertNotNull(item);
		assertEquals("123", item.getFileID());
		if (fs instanceof IndexedLocalFileSystem) {
			assertNotNull(fs.getItem("123"));
		}

		flushFileSystemEvents();
		events.clear();

		fs.moveItem("/abc", "greg", "/xyz", "bob");

		if (fs instanceof IndexedLocalFileSystem) {
			assertNotNull(fs.getItem("123"));
		}
		assertNull(fs.getItem("/abc", "greg"));
		assertNotNull(fs.getItem("/xyz", "bob"));

		flushFileSystemEvents();
		assertEquals(2, events.size());
		checkEvent("Folder Created", "/", "xyz", null, null, events.get(0));
		checkEvent("Item Moved", "/abc", "greg", "/xyz", "bob", events.get(1));
	}

//	public void testDeleteDataFile() throws Exception {
//		fs.createFolder("/","abc");
//		DataFileItem df = fs.createDataFile("/abc","fred", null, "Data", null);	
//		events.clear();
//		
//		df.delete();
//		assertNull(fs.getItem("/abc", "fred"));
//		assertEquals(1, events.size());
//		checkEvent("Item Deleted", "/abc", "fred", null, null, events.get(0));
//	}
//
	@Test
	public void testDeleteDatabase() throws Exception {
		fs.createFolder("/", "abc");
		DBHandle dbh = new DBHandle();
		long id = dbh.startTransaction();
		dbh.createTable("test",
			new Schema(0, "key", new Field[] { IntField.INSTANCE }, new String[] { "dummy" }));
		dbh.endTransaction(id, true);
		BufferFile bf =
			fs.createDatabase("/abc", "greg", "123", "Database", dbh.getBufferSize(), "test", null);
		dbh.saveAs(bf, true, TaskMonitor.DUMMY);
		dbh.close();

		FolderItem item = fs.getItem("/abc", "greg");
		assertNotNull(item);
		assertEquals("123", item.getFileID());
		if (fs instanceof IndexedLocalFileSystem) {
			assertNotNull(fs.getItem("123"));
		}

		flushFileSystemEvents();
		events.clear();

		item.delete(-1, "test");

		if (fs instanceof IndexedLocalFileSystem) {
			assertNull(fs.getItem("123"));
		}
		assertNull(fs.getItem("/abc", "greg"));

		flushFileSystemEvents();
		assertEquals(1, events.size());
		checkEvent("Item Deleted", "/abc", "greg", null, null, events.get(0));
	}

	@Test
	public void testItemChanged() throws Exception {
		fs.createFolder("/", "abc");
		DataFileItem df = fs.createDataFile("/abc", "fred", null, "Data", "DataFile", null);

		flushFileSystemEvents();
		events.clear();

		df.setReadOnly(true);
		df = (DataFileItem) fs.getItem("/abc", "fred");
		assertTrue(df.isReadOnly());
		assertEquals(1, events.size());
		checkEvent("Item Changed", "/abc", "fred", null, null, events.get(0));
	}
//
//	public void testMoveItem() throws Exception {
//		fs.createFolder("/","abc");
//		String data = "This is a test";
//		byte[] dataBytes = data.getBytes();
//		DBHandle dbh = new DBHandle();
//		long id = dbh.startTransaction();
//		dbh.createTable("test", new Schema(0,"key", new Class[]{IntField.class}, new String[] {"dummy"} ));
//		dbh.endTransaction(id, true);
//		DataFileItem df = fs.createDataFile("/abc","fred", new ByteArrayInputStream(dataBytes), "Data", null);	
//		DataFileItem df2 = fs.createDataFile("/abc","bob", new ByteArrayInputStream(dataBytes), "Data", null);	
//		DatabaseItem db = fs.createDatabase("/abc","greg", dbh, "Database", null);	
//		dbh.close();
//
//		events.clear();
//		fs.moveItem("/abc", "fred", "/def");
//		String[] items = fs.getItemNames("/def");
//		assertEquals(1, items.length);
//		assertEquals("fred", items[0]);
//		df = (DataFileItem)fs.getItem("/def",items[0]);
//		InputStream is = df.getInputStream();
//		byte[] buffer = new byte[1024];
//		int n = is.read(buffer);
//		is.close();
//		assertEquals(dataBytes.length, n);
//		String s = new String(buffer, 0, n);
//		assertEquals(data, s);
//		
//		assertEquals(2, events.size());
//		checkEvent("Item Moved", "/abc", "fred", "/def", null, events.get(1));
//
//		 
//		
//		fs.moveItem("/abc", "greg", "/def");
//		items = fs.getItemNames("/def");
//		assertEquals(2, items.length);
//		assertEquals("greg", items[1]);
//
//		db = (DatabaseItem)fs.getItem("/def", items[1]);
//		dbh = db.open(true);
//		assertNotNull(dbh.getTable("test"));
//		dbh.close();
//
//		df = fs.createDataFile("/abc", "fred", null, "Data", null);
//		try {
//			fs.moveItem("/abc", "fred", "/def");
//			Assert.fail();
//		}catch(DuplicateFileException e) {
//		}
//
//		dbh = db.open(true);
//		try {
//			fs.moveItem("/def", "greg", "/hij");
//			Assert.fail();
//		}catch(FileInUseException e) {
//		}finally {
//			dbh.close();
//		}
//	}
//	private void deleteAll(File file) {
//		if (file.isDirectory()) {
//			File[] files = file.listFiles();
//			for (int i = 0; i < files.length; i++) {
//				deleteAll(files[i]);
//			}
//		}
//		file.delete();
//	}

	private void createDatabase(String folderPath, String itemName, String fileId)
			throws Exception {
		if (!folderPath.startsWith("/")) {
			fail("folderPath must be absolute: " + folderPath);
		}

		String path = "/";
		String fp = folderPath;
		while (fp.length() != 0) {
			int index = fp.indexOf('/', 1);
			String n = fp.substring(1);
			if (index == 1) {
				fp = n;
				continue;
			}
			else if (index > 0) {
				n = fp.substring(1, index);
				fp = fp.substring(index);
			}
			else {
				fp = "";
			}
			fs.createFolder(path, n);
			if (!path.endsWith("/")) {
				path += "/";
			}
			path += n;
		}

		DBHandle dbh = new DBHandle();
		long id = dbh.startTransaction();
		dbh.createTable("test",
			new Schema(0, "key", new Field[] { IntField.INSTANCE }, new String[] { "dummy" }));
		dbh.endTransaction(id, true);
		BufferFile bf = fs.createDatabase(folderPath, itemName, fileId, "Database",
			dbh.getBufferSize(), "test", null);
		dbh.saveAs(bf, true, TaskMonitor.DUMMY);
		dbh.close();
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
			// not tracked
		}
	}

	private void flushFileSystemEvents() {
		FileSystemEventManager eventManager =
			(FileSystemEventManager) TestUtils.getInstanceField("eventManager", fs);

		try {
			eventManager.flushEvents(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			failWithException("Interrupted waiting for filesystem events", e);
		}
	}
}

class MyEvent {
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((newName == null) ? 0 : newName.hashCode());
		result = prime * result + ((newParentPath == null) ? 0 : newParentPath.hashCode());
		result = prime * result + ((op == null) ? 0 : op.hashCode());
		result = prime * result + ((parentPath == null) ? 0 : parentPath.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		MyEvent other = (MyEvent) obj;
		return eq(op, other.op) && eq(parentPath, other.parentPath) && eq(name, other.name) &&
			eq(newParentPath, other.newParentPath) && eq(newName, other.newName);
	}

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

	private boolean eq(String s1, String s2) {
		return Objects.equals(s1, s2);
	}

	@Override
	public String toString() {
		return op + " " + parentPath + " " + name + " " + newParentPath + " " + newName;
	}

}
