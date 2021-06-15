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
package ghidra.framework.store.db;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import org.junit.*;

import db.*;
import db.buffers.BufferFile;
import db.buffers.LocalBufferFile;
import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

public class PackedDatabaseTest extends AbstractGenericTest {

	private static final Schema TEST_SCHEMA =
		new Schema(1, "Key", new Field[] { StringField.INSTANCE }, new String[] { "Col1" });

	private File packedDbFile;
	private PackedDatabase db;
	private PackedDBHandle dbh;
	private PackedDatabase db2;
	private PackedDBHandle dbh2;

	public PackedDatabaseTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		String path = createTempFilePath("packed.db", ".pf");
		packedDbFile = new File(path);
	}

	@After
	public void tearDown() throws Exception {
		PackedDatabaseCache cache = PackedDatabaseCache.getCache();
		if (cache != null) { // clean-out cacheDir
			File cacheDir = (File) getInstanceField("cacheDir", cache);
			FileUtilities.deleteDir(cacheDir);
			cacheDir.mkdir();
		}
		if (dbh != null) {
			dbh.close();
		}
		if (db != null) {
			ResourceFile pf = db.getPackedFile();
			db.dispose();
			pf.delete();
		}
		if (dbh2 != null) {
			dbh2.close();
		}
		if (db2 != null) {
			ResourceFile pf = db2.getPackedFile();
			db2.dispose();
			pf.delete();
		}

	}

	private long createPackedDatabase() throws Exception {

		// Create simple database
		dbh = new PackedDBHandle("MyContent");
		long txId = dbh.startTransaction();
		Table table = dbh.createTable("MyTable", TEST_SCHEMA);
		DBRecord rec = TEST_SCHEMA.createRecord(1);
		rec.setString(0, "String1");
		table.putRecord(rec);
		dbh.endTransaction(txId, true);

		// Create new packed db file
		db = dbh.saveAs("Test1", packedDbFile.getParentFile(), packedDbFile.getName(), null);
		long id = dbh.getDatabaseId();
		dbh.close();
		dbh = null;
		db.dispose();

		return id;
	}

	@Test
	public void testCreatePackedDatabase() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only and verify content
		db = PackedDatabase.getPackedDatabase(packedDbFile, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals("MyContent", db.getContentType());
		dbh = (PackedDBHandle) db.open(null);

		Table table = dbh.getTable("MyTable");
		assertNotNull(table);
		assertEquals(1, table.getRecordCount());

		DBRecord rec = table.getRecord(1);
		assertNotNull(rec);
		assertEquals("String1", rec.getString(0));

		// Second open should fail
		try {
			dbh2 = (PackedDBHandle) db.openForUpdate(null);
			Assert.fail();
		}
		catch (IOException e) {
			// expected failure
		}

		// Close first one
		dbh.close();
		db.dispose();

		// open for update
		db = PackedDatabase.getPackedDatabase(packedDbFile, true, TaskMonitorAdapter.DUMMY_MONITOR);
		dbh = (PackedDBHandle) db.openForUpdate(null);

		// add record - hold for update
		long txId = dbh.startTransaction();
		table = dbh.getTable("MyTable");
		rec = TEST_SCHEMA.createRecord(2);
		rec.setString(0, "String2");
		table.putRecord(rec);
		dbh.endTransaction(txId, true);
		dbh.save(null);

		// Test concurrent access by another user
		db2 = PackedDatabase.getPackedDatabase(packedDbFile, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals("MyContent", db2.getContentType());

		// Second update access should fail
		try {
			dbh2 = (PackedDBHandle) db2.openForUpdate(null);
			Assert.fail();
		}
		catch (IOException e) {
			// expected lock failure
		}

		// Read-only access should be allowed
		dbh2 = (PackedDBHandle) db2.open(null);

		Table table2 = dbh2.getTable("MyTable");
		assertNotNull(table2);
		assertEquals(2, table2.getRecordCount());

		rec = table2.getRecord(1);
		assertNotNull(rec);
		assertEquals("String1", rec.getString(0));

		rec = table2.getRecord(2);
		assertNotNull(rec);
		assertEquals("String2", rec.getString(0));

	}

	@Test
	public void testCreatePackedDatabaseWithSpecificId() throws Exception {

		long id = createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only
		db = PackedDatabase.getPackedDatabase(packedDbFile, true, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals("MyContent", db.getContentType());
		dbh = (PackedDBHandle) db.open(null);
		assertEquals(id, dbh.getDatabaseId());

		// Create new packed db file with different id
		File newFile = new File(packedDbFile.getParentFile(), packedDbFile.getName() + "a");
		File anotherNewFile = new File(packedDbFile.getParentFile(), packedDbFile.getName() + "b");
		try {
			long newId = 0x12345678L;
			db = dbh.saveAs("Test2", newFile.getParentFile(), newFile.getName(), newId, null);
			assertEquals(newId, dbh.getDatabaseId());

			db = dbh.saveAs("Test3", anotherNewFile.getParentFile(), anotherNewFile.getName(),
				newId, null);
			assertEquals(newId, dbh.getDatabaseId());

			dbh.close();
			dbh = null;
			db.dispose();

			// Open packed db as read-only
			db = PackedDatabase.getPackedDatabase(anotherNewFile, TaskMonitorAdapter.DUMMY_MONITOR);
			assertEquals("MyContent", db.getContentType());
			dbh = (PackedDBHandle) db.open(null);
			assertEquals(newId, dbh.getDatabaseId());
		}
		finally {
			if (dbh != null) {
				dbh.close();
				dbh = null;
			}
			newFile.delete();
			anotherNewFile.delete();
		}
	}

	@Test
	public void testDispose() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only and verify content
		db = PackedDatabase.getPackedDatabase(packedDbFile, true, TaskMonitorAdapter.DUMMY_MONITOR);
		File dbDir = (File) getInstanceField("dbDir", db);
		File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		db.dispose();

		assertTrue(!dbDir.exists());
		assertTrue(!tmpDbDir.exists());
	}

	@Test
	public void testDispose_Cached() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only and verify content
		db = PackedDatabase.getPackedDatabase(packedDbFile, TaskMonitorAdapter.DUMMY_MONITOR);
		File dbDir = (File) getInstanceField("dbDir", db);
		File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		db.dispose();

		assertTrue(dbDir.exists());
		assertTrue(!tmpDbDir.exists());
	}

	@Test
	public void testAutoDisposeOnClose() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only and verify content
		db = PackedDatabase.getPackedDatabase(packedDbFile, true, TaskMonitorAdapter.DUMMY_MONITOR);
		File dbDir = (File) getInstanceField("dbDir", db);
		File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");

		dbh = (PackedDBHandle) db.open(TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		dbh.close();

		assertTrue(!dbDir.exists());
		assertTrue(!tmpDbDir.exists());
	}

	@Test
	public void testCache() throws Exception {

		createPackedDatabase();

		File commaFile = new File(packedDbFile.getParentFile(), "a,b,c,d.pdb");
		commaFile.delete();
		assertFalse(commaFile.exists());
		packedDbFile.renameTo(commaFile);
		assertTrue(commaFile.exists());

		PackedDatabaseCache cache = PackedDatabaseCache.getCache();
		assertTrue(PackedDatabaseCache.isEnabled());

		ResourceFile dbFile = new ResourceFile(commaFile);
		cache.purgeFromCache(dbFile);
		assertFalse(cache.isInCache(dbFile));

		try {
			// Open packed db as read-only and verify content
			db = PackedDatabase.getPackedDatabase(commaFile, TaskMonitorAdapter.DUMMY_MONITOR);
			File dbDir = (File) getInstanceField("dbDir", db);

			dbh = (PackedDBHandle) db.open(TaskMonitorAdapter.DUMMY_MONITOR);

			assertTrue(dbDir.isDirectory());
			assertTrue(cache.isInCache(dbFile));

			dbh.close();
			db.dispose();

			assertTrue(dbDir.exists());
			assertTrue(cache.isInCache(dbFile));

			PackedDatabase cachedDB = cache.getCachedDB(dbFile, TaskMonitorAdapter.DUMMY_MONITOR);
			assertNotNull(cachedDB);
			cachedDB.dispose();

			assertTrue(dbDir.exists());
			assertTrue(cache.isInCache(dbFile));

			// reopen
			db = PackedDatabase.getPackedDatabase(commaFile, TaskMonitorAdapter.DUMMY_MONITOR);
			dbh = (PackedDBHandle) db.open(TaskMonitorAdapter.DUMMY_MONITOR);

			assertEquals(dbDir, getInstanceField("dbDir", db));

			assertTrue(cache.isInCache(dbFile));

			dbh.close();
			db.dispose();
		}
		finally {
			cache.purgeFromCache(dbFile);
		}
	}

	@Test
	public void testAutoDisposeOnClose_Cached() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		PackedDatabaseCache cache = PackedDatabaseCache.getCache();
		assertTrue(PackedDatabaseCache.isEnabled());

		ResourceFile dbFile = new ResourceFile(packedDbFile);
		cache.purgeFromCache(dbFile);
		assertFalse(cache.isInCache(dbFile));

		try {
			// Open packed db as read-only and verify content
			db = PackedDatabase.getPackedDatabase(packedDbFile, TaskMonitorAdapter.DUMMY_MONITOR);
			File dbDir = (File) getInstanceField("dbDir", db);
			File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");

			dbh = (PackedDBHandle) db.open(TaskMonitorAdapter.DUMMY_MONITOR);

			assertTrue(dbDir.isDirectory());
			assertTrue(!tmpDbDir.exists());
			assertTrue(cache.isInCache(dbFile));

			dbh.close();

			assertTrue(dbDir.exists());
			assertTrue(!tmpDbDir.exists());
			assertTrue(cache.isInCache(dbFile));

		}
		finally {
			cache.purgeFromCache(dbFile);
		}
	}

	@Test
	public void testAutoDisposeOnSaveAs() throws Exception {

		createPackedDatabase();

		assertTrue(packedDbFile.exists());

		// Open packed db as read-only and verify content
		db = PackedDatabase.getPackedDatabase(packedDbFile, true, TaskMonitorAdapter.DUMMY_MONITOR);
		File dbDir = (File) getInstanceField("dbDir", db);
		File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");

		File tmpFile1 = createTempFile(getName() + "1", ".gbf");
		tmpFile1.delete();
		File tmpFile2 = createTempFile(getName() + "2", ".gbf");
		tmpFile2.delete();

		BufferFile bf = null;

		dbh = (PackedDBHandle) db.open(TaskMonitorAdapter.DUMMY_MONITOR);

		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		bf = new LocalBufferFile(tmpFile1, dbh.getBufferSize());
		dbh.saveAs(bf, false, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(bf.isReadOnly());
		bf.dispose();

		// original dbh still refers to unpacked database
		assertTrue(dbDir.isDirectory());
		assertTrue(!tmpDbDir.exists());

		assertTrue(tmpFile1.exists()); // still in-use

		bf = new LocalBufferFile(tmpFile2, dbh.getBufferSize());
		dbh.saveAs(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(bf.isReadOnly());

		assertTrue(tmpFile1.exists()); // no longer in-use
		assertTrue(tmpFile1.delete());

		// original dbh now refers to new database - original packed database should close
		assertTrue(!dbDir.exists());
		assertTrue(!tmpDbDir.exists());

		assertTrue(tmpFile2.exists()); // no longer in-use
		dbh.close(); // must close before removing
		assertTrue(tmpFile2.delete());

	}

}
