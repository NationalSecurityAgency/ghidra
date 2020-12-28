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
package db;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.*;

import db.buffers.BufferFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.store.DatabaseItem;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

public class RecoveryDBTest extends AbstractGenericTest {

	private static int BUFFER_SIZE = 512;
	private static int RECORD_COUNT = 1000;

	private static Schema SCHEMA =
		new Schema(1, "key", new Field[] { StringField.INSTANCE }, new String[] { "field1" });

	private static final File testDir =
		new File(AbstractGenericTest.getTestDirectoryPath(), "test");

	private LocalFileSystem fileSystem;

	/**
	 * Constructor for RecoveryFileTest.
	 * @param arg0
	 */
	public RecoveryDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		FileUtilities.deleteDir(testDir);
		testDir.mkdir();
		fileSystem =
			LocalFileSystem.getLocalFileSystem(testDir.getPath(), true, false, false, true);
	}

	@After
	public void tearDown() throws Exception {
		fileSystem.dispose();
		FileUtilities.deleteDir(testDir);

	}

	/**
	 *
	 * File created:
	 *
	 *
	 * Recovery snapshot taken after each transaction.
	 * Transaction 1:
	 *
	 * Transaction 2:
	 *
	 * Transaction 3:
	 *
	 * Transaction 4:
	 *
	 *
	 * @throws Exception
	 */
	private DBHandle init(int initialRecCnt) throws Exception {

		DBHandle dbh = new DBHandle(BUFFER_SIZE);
		BufferFile bf =
			fileSystem.createDatabase("/", "testDb", null, "Test", dbh.getBufferSize(), null, null);
		dbh.saveAs(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);
		dbh.close();
		bf.dispose();

		DatabaseItem dbItem = (DatabaseItem) fileSystem.getItem("/", "testDb");
		assertTrue(!dbItem.canRecover());
		bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
		dbh = new DBHandle(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

		long txId = dbh.startTransaction();
		Table table1 = dbh.createTable("table1", SCHEMA);
		tableFill(table1, initialRecCnt, "initTable1_");
		dbh.endTransaction(txId, true);

		txId = dbh.startTransaction();
		tableDelete(table1, initialRecCnt, 0, 2);
		dbh.endTransaction(txId, true);

		assertTrue(dbh.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

		txId = dbh.startTransaction();
		Table table2 = dbh.createTable("table2", SCHEMA);
		tableFill(table2, initialRecCnt, "initTable2_");
		dbh.endTransaction(txId, true);

		txId = dbh.startTransaction();
		tableDelete(table2, initialRecCnt, 0, 2);
		dbh.endTransaction(txId, true);

		assertTrue(dbh.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

		return dbh;
	}

	private void tableFill(Table table, int recCnt, String baseName) throws Exception {
		for (int i = 0; i < recCnt; i++) {
			DBRecord rec = SCHEMA.createRecord(i);
			rec.setString(0, baseName + i);
			table.putRecord(rec);
		}
	}

	private void tableDelete(Table table, int recCnt, int startKey, int inc) throws Exception {
		for (int i = startKey; i < recCnt; i += inc) {
			table.deleteRecord(i);
		}
	}

	@Test
	public void testRecovery() throws Exception {

		DBHandle dbh = init(RECORD_COUNT);
		DBHandle dbh2 = null;
		try {
			DatabaseItem dbItem = (DatabaseItem) fileSystem.getItem("/", "testDb");
			assertTrue(dbItem.canRecover());
			BufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
			dbh2 = new DBHandle(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

			Table table1 = dbh2.getTable("table1");
			assertNotNull(table1);
			assertEquals(RECORD_COUNT / 2, table1.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNull(rec);
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable1_" + i, rec.getString(0));
			}

			Table table2 = dbh2.getTable("table2");
			assertNotNull(table2);
			assertEquals(RECORD_COUNT / 2, table2.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				assertNull(table2.getRecord(i));
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table2.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable2_" + i, rec.getString(0));
			}
		}
		finally {
			dbh.close();
			if (dbh2 != null) {
				dbh2.close();
			}
		}

	}

	@Test
	public void testRecoveryWithUndo() throws Exception {

		DBHandle dbh = init(RECORD_COUNT);
		DBHandle dbh2 = null;
		try {

			assertTrue(dbh.undo());
			assertTrue(dbh.undo());

			assertTrue(dbh.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			DatabaseItem dbItem = (DatabaseItem) fileSystem.getItem("/", "testDb");
			assertTrue(dbItem.canRecover());
			BufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
			dbh2 = new DBHandle(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

			Table table1 = dbh2.getTable("table1");
			assertNotNull(table1);
			assertEquals(RECORD_COUNT / 2, table1.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNull(rec);
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable1_" + i, rec.getString(0));
			}

			assertNull(dbh.getTable("table2"));
			assertNull(dbh2.getTable("table2"));

		}
		finally {
			dbh.close();
			if (dbh2 != null) {
				dbh2.close();
			}
		}

	}

	@Test
	public void testRecoveryWithUndoRedo() throws Exception {

		DBHandle dbh = init(RECORD_COUNT);
		DBHandle dbh2 = null;
		try {

			assertTrue(dbh.undo());
			assertTrue(dbh.undo());

			assertTrue(dbh.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			assertTrue(dbh.redo());
			assertTrue(dbh.redo());

			assertTrue(dbh.takeRecoverySnapshot(null, TaskMonitorAdapter.DUMMY_MONITOR));

			assertNotNull(dbh.getTable("table2"));

			DatabaseItem dbItem = (DatabaseItem) fileSystem.getItem("/", "testDb");
			assertTrue(dbItem.canRecover());
			BufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
			dbh2 = new DBHandle(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

			Table table1 = dbh2.getTable("table1");
			assertNotNull(table1);
			assertEquals(RECORD_COUNT / 2, table1.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNull(rec);
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable1_" + i, rec.getString(0));
			}

			Table table2 = dbh2.getTable("table2");
			assertNotNull(table2);
			assertEquals(RECORD_COUNT / 2, table2.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				assertNull(table2.getRecord(i));
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table2.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable2_" + i, rec.getString(0));
			}
		}
		finally {
			dbh.close();
			if (dbh2 != null) {
				dbh2.close();
			}
		}

	}

	@Test
	public void testRecoveryWithSave() throws Exception {

		DBHandle dbh = init(RECORD_COUNT);
		DBHandle dbh2 = null;
		try {
			DatabaseItem dbItem = (DatabaseItem) fileSystem.getItem("/", "testDb");
			assertTrue(dbItem.canRecover());
			BufferFile bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
			dbh2 = new DBHandle(bf, true, TaskMonitorAdapter.DUMMY_MONITOR);

			dbh2.save(null, null, TaskMonitorAdapter.DUMMY_MONITOR);
			dbh2.close();

			assertTrue(!dbItem.canRecover());
			bf = dbItem.openForUpdate(FolderItem.DEFAULT_CHECKOUT_ID);
			dbh2 = new DBHandle(bf);

			Table table1 = dbh2.getTable("table1");
			assertNotNull(table1);
			assertEquals(RECORD_COUNT / 2, table1.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNull(rec);
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table1.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable1_" + i, rec.getString(0));
			}

			Table table2 = dbh2.getTable("table2");
			assertNotNull(table2);
			assertEquals(RECORD_COUNT / 2, table2.getRecordCount());

			for (int i = 0; i < RECORD_COUNT; i += 2) {
				assertNull(table2.getRecord(i));
			}

			for (int i = 1; i < RECORD_COUNT; i += 2) {
				DBRecord rec = table2.getRecord(i);
				assertNotNull(rec);
				assertEquals("initTable2_" + i, rec.getString(0));
			}
		}
		finally {
			dbh.close();
			if (dbh2 != null) {
				dbh2.close();
			}
		}

	}
}
