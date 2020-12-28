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
import java.io.IOException;
import java.util.Arrays;

import org.junit.*;

import db.buffers.*;
import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import utilities.util.FileUtilities;

/**
 * Test the creation of a new database with indexed and non-indexed tables.
 * Tests include the removal of tables and are performed for both a stored and
 * non-stored database.
 */
public class DBTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private File testDir;
	private static final String dbName = "test";
	private static final String dbName2 = "test2";

	private BufferFileManager fileMgr;
	private DBHandle dbh;
	private BufferFile bfile;

	@Before
	public void setUp() throws Exception {

		testDir = createTempDirectory(getClass().getSimpleName());
		dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
	}

	@After
	public void tearDown() throws Exception {
		if (dbh != null) {
			dbh.close();
		}
		if (bfile != null) {
			bfile.close();
		}
		FileUtilities.deleteDir(testDir);
	}

	private void saveAsAndReopen(String name) throws IOException {
		try {
			BufferFileManager mgr = DBTestUtils.getBufferFileManager(testDir, name);
			BufferFile bf = new LocalManagedBufferFile(dbh.getBufferSize(), mgr, -1);
			dbh.saveAs(bf, true, null);
			dbh.close();
			fileMgr = mgr;
		}
		catch (CancelledException e) {
			Assert.fail("Should not happen");
		}
		bfile = new LocalManagedBufferFile(fileMgr, true, -1, -1);
		dbh = new DBHandle(bfile);
	}

	private void saveAndReopen() throws IOException {
		assertTrue(dbh.canUpdate());
		long dbId = dbh.getDatabaseId();
		try {
			dbh.save(null, null, null);
		}
		catch (CancelledException e) {
			Assert.fail("Should not happen");
		}
		dbh.close();
		bfile = new LocalManagedBufferFile(fileMgr, true, -1, -1);
		dbh = new DBHandle(bfile);
		assertEquals(dbId, dbh.getDatabaseId());
	}

	@Test
	public void testCreateDatabase() {

		assertTrue(!dbh.canUpdate());
		assertTrue(!dbh.canRedo());
		assertTrue(!dbh.canUndo());

		try {
			dbh.checkTransaction();
			Assert.fail();
		}
		catch (NoTransactionException e) {
			// expected
		}

		assertEquals(dbh.getTableCount(), 0);
	}

	@Test
	public void testCreateExistingDatabase() throws IOException {
		saveAsAndReopen(dbName);
		try {
			saveAsAndReopen(dbName);
			Assert.fail();
		}
		catch (DuplicateFileException e) {
			// good; expected
		}
	}

	@Test
	public void testCreateDatabaseCopies() throws IOException {
		long dbId = dbh.getDatabaseId();
		saveAsAndReopen(dbName);
		assertTrue(dbId == dbh.getDatabaseId());// First SaveAs should preserve ID
		try {
			saveAsAndReopen(dbName2);
			assertTrue(dbId != dbh.getDatabaseId());// Second SaveAs should change ID to avoid duplication
		}
		catch (DuplicateFileException e) {
			Assert.fail();
		}
	}

	@Test
	public void testOpenForReadOnlyDuringUpdate() throws IOException {
		saveAsAndReopen(dbName);

		BufferFile bf2 = new LocalManagedBufferFile(fileMgr, false, -1, -1);
		DBHandle dbh2 = null;
		try {
			dbh2 = new DBHandle(bf2);
			createNonIndexedTables(false, DBTestUtils.MAX_SCHEMA_TYPE + 1);
			saveAndReopen();
			assertEquals(DBTestUtils.MAX_SCHEMA_TYPE + 1, dbh.getTableCount());
			assertEquals(0, dbh2.getTableCount());
		}
		finally {
			if (dbh2 != null) {
				dbh2.close();
			}
			bf2.close();
		}
	}

	@Test
	public void testCreateLongKeyTable() throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createLongKeyTable(dbh, "TABLE1", DBTestUtils.ALL_TYPES, false, false);
		dbh.endTransaction(txId, true);
		String[] names = table.getSchema().getFieldNames();
		assertTrue(Arrays.equals(DBTestUtils.getFieldNames(DBTestUtils.ALL_TYPES), names));
	}

	@Test
	public void testCreateVarKeyTable() throws IOException {
		long txId = dbh.startTransaction();
		Table table = DBTestUtils.createBinaryKeyTable(dbh, "TABLE1", DBTestUtils.ALL_TYPES, false);
		dbh.endTransaction(txId, true);
		String[] names = table.getSchema().getFieldNames();
		assertTrue(Arrays.equals(DBTestUtils.getFieldNames(DBTestUtils.ALL_TYPES), names));
	}

	@Test
	public void testStoredCreateLongKeyTable() throws IOException {
		long txId = dbh.startTransaction();
		DBTestUtils.createLongKeyTable(dbh, "TABLE1", DBTestUtils.ALL_TYPES, false, false);
		dbh.endTransaction(txId, true);
		saveAsAndReopen(dbName);
		Table table = dbh.getTable("TABLE1");
		assertTrue(table.useLongKeys());
		String[] names = table.getSchema().getFieldNames();
		assertTrue(Arrays.equals(DBTestUtils.getFieldNames(DBTestUtils.ALL_TYPES), names));
	}

	@Test
	public void testStoredCreateVarKeyTable() throws IOException {
		long txId = dbh.startTransaction();
		DBTestUtils.createBinaryKeyTable(dbh, "TABLE1", DBTestUtils.ALL_TYPES, false);
		dbh.endTransaction(txId, true);
		saveAsAndReopen(dbName);
		Table table = dbh.getTable("TABLE1");
		assertTrue(!table.useLongKeys());
		assertTrue(table.getSchema().getKeyFieldType().getClass().equals(BinaryField.class));
		String[] names = table.getSchema().getFieldNames();
		assertTrue(Arrays.equals(DBTestUtils.getFieldNames(DBTestUtils.ALL_TYPES), names));
	}

	private void createNonIndexedTables(boolean testStoredDB, int cnt) throws IOException {

		// Create table for each schema defined by DBTestUtils
		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i++) {
			DBTestUtils.createLongKeyTable(dbh, "TABLE" + i, i % (DBTestUtils.MAX_SCHEMA_TYPE + 1),
				false, false);
		}
		dbh.endTransaction(txId, true);
		assertEquals(cnt, dbh.getTableCount());

		if (testStoredDB) {
			saveAsAndReopen(dbName);
			assertEquals(cnt, dbh.getTableCount());
		}

		// Check Master Table entries
		TableRecord[] tableRecords = dbh.getMasterTable().getTableRecords();
		for (int i = 0; i < tableRecords.length; i++) {
			String name = "TABLE" + i;
			assertEquals(name, tableRecords[i].getName());
			assertEquals(-1, tableRecords[i].getIndexedColumn());
			assertEquals(Long.MIN_VALUE, tableRecords[i].getMaxKey());
			assertEquals(0, tableRecords[i].getRecordCount());
			assertEquals(-1, tableRecords[i].getRootBufferId());
		}
	}

	@Test
	public void testNonIndexedTables() throws IOException {
		createNonIndexedTables(false, DBTestUtils.MAX_SCHEMA_TYPE + 1);
	}

	@Test
	public void testStoredNonIndexedTables() throws IOException {
		createNonIndexedTables(true, DBTestUtils.MAX_SCHEMA_TYPE + 1);
	}

	private void createIndexedTables(boolean testStoredDB) throws IOException {

		// Create table for each schema defined by DBTestUtils
		// All schema fields are indexed
		long txId = dbh.startTransaction();
		for (int i = 0; i <= DBTestUtils.MAX_SCHEMA_TYPE; i++) {
			DBTestUtils.createLongKeyTable(dbh, "TABLE" + i, i, true, false);
		}
		assertEquals(DBTestUtils.MAX_SCHEMA_TYPE + 1, dbh.getTableCount());
		dbh.endTransaction(txId, true);

		if (testStoredDB) {
			saveAsAndReopen(dbName);
			assertEquals(DBTestUtils.MAX_SCHEMA_TYPE + 1, dbh.getTableCount());
		}

		// Check Master Table entries
		TableRecord[] tableRecords = dbh.getMasterTable().getTableRecords();
		Table lastTable = null;
		int tableCnt = 0;
		int indexCnt = 0;
		for (TableRecord tableRecord : tableRecords) {
			if (tableRecord.getIndexedColumn() < 0) {
				if (tableCnt > 0) {
					assertEquals(DBTestUtils.getIndexedColumnCount(tableCnt - 1), indexCnt);
				}
				String name = "TABLE" + tableCnt;
				lastTable = dbh.getTable(name);
				assertEquals(name, tableRecord.getName());
				assertEquals(Long.MIN_VALUE, tableRecord.getMaxKey());
				assertEquals(0, tableRecord.getRecordCount());
				assertEquals(-1, tableRecord.getRootBufferId());
				++tableCnt;
				indexCnt = 0;
			}
			else {
				if (lastTable == null) {
					Assert.fail();
				}
				int[] indexedColumns = DBTestUtils.getIndexedColumns(tableCnt - 1);
				assertTrue(indexCnt < indexedColumns.length);
				assertEquals(indexedColumns[indexCnt], tableRecord.getIndexedColumn());
				assertEquals(lastTable.getName(), tableRecord.getName());
				assertEquals(Long.MIN_VALUE, tableRecord.getMaxKey());
				assertEquals(0, tableRecord.getRecordCount());
				assertEquals(-1, tableRecord.getRootBufferId());
				++indexCnt;
			}

		}
		assertEquals(DBTestUtils.getIndexedColumnCount(tableCnt - 1), indexCnt);
		assertEquals(DBTestUtils.MAX_SCHEMA_TYPE + 1, tableCnt);

	}

	@Test
	public void testIndexedTables() throws IOException {
		createIndexedTables(false);
	}

	@Test
	public void testStoredIndexedTables() throws IOException {
		createIndexedTables(true);
	}

	private void removeNonIndexedTables(boolean testStoredDB) throws IOException {

		// Create table for each schema defined by DBTestUtils
		createNonIndexedTables(testStoredDB, DBTestUtils.MAX_SCHEMA_TYPE + 1);

		// Delete odd numbered tables
		long txId = dbh.startTransaction();
		int totalTableCnt = 0;
		for (int i = 0; i <= DBTestUtils.MAX_SCHEMA_TYPE; i++) {
			if ((i % 2) == 1) {
				dbh.deleteTable("TABLE" + i);
			}
			else {
				++totalTableCnt;
			}
		}
		dbh.endTransaction(txId, true);
		assertEquals(totalTableCnt, dbh.getTableCount());

		if (testStoredDB) {
			saveAndReopen();
			assertEquals(totalTableCnt, dbh.getTableCount());
		}

		// Check Master Table entries
		TableRecord[] tableRecords = dbh.getMasterTable().getTableRecords();
		for (int i = 0; i < tableRecords.length; i++) {
			String name = "TABLE" + (2 * i);
			assertEquals(name, tableRecords[i].getName());
			assertEquals(-1, tableRecords[i].getIndexedColumn());
			assertEquals(Long.MIN_VALUE, tableRecords[i].getMaxKey());
			assertEquals(0, tableRecords[i].getRecordCount());
			assertEquals(-1, tableRecords[i].getRootBufferId());
		}
		assertEquals(totalTableCnt, tableRecords.length);

	}

	@Test
	public void testRemoveNonIndexedTables() throws IOException {
		removeNonIndexedTables(false);
	}

	@Test
	public void testStoredRemoveNonIndexedTables() throws IOException {
		removeNonIndexedTables(true);
	}

	private void removeIndexedTables(boolean testStoredDB) throws IOException {

		// Create table for each schema defined by DBTestUtils
		// All schema fields are indexed
		createIndexedTables(testStoredDB);

		// Delete odd numbered tables
		long txId = dbh.startTransaction();
		int totalTableCnt = 0;
		for (int i = 0; i <= DBTestUtils.MAX_SCHEMA_TYPE; i++) {
			if ((i % 2) == 1) {
				dbh.deleteTable("TABLE" + i);
			}
			else {
				++totalTableCnt;
			}
		}
		dbh.endTransaction(txId, true);
		assertEquals(totalTableCnt, dbh.getTableCount());

		if (testStoredDB) {
			saveAndReopen();
			assertEquals(totalTableCnt, dbh.getTableCount());
		}

		// Check Master Table entries
		TableRecord[] tableRecords = dbh.getMasterTable().getTableRecords();
		Table lastTable = null;
		int tableCnt = 0;
		int indexCnt = 0;
		for (TableRecord tableRecord : tableRecords) {
			if (tableRecord.getIndexedColumn() < 0) {
				if (tableCnt > 0) {
					assertEquals(DBTestUtils.getIndexedColumnCount(2 * (tableCnt - 1)), indexCnt);
				}
				String name = "TABLE" + (2 * tableCnt);
				lastTable = dbh.getTable(name);
				assertEquals(name, tableRecord.getName());
				assertEquals(Long.MIN_VALUE, tableRecord.getMaxKey());
				assertEquals(0, tableRecord.getRecordCount());
				assertEquals(-1, tableRecord.getRootBufferId());
				++tableCnt;
				indexCnt = 0;
			}
			else {
				if (lastTable == null) {
					Assert.fail();
				}
				int[] indexedColumns = DBTestUtils.getIndexedColumns(2 * (tableCnt - 1));
				assertTrue(indexCnt < indexedColumns.length);
				assertEquals(indexedColumns[indexCnt], tableRecord.getIndexedColumn());
				assertEquals(lastTable.getName(), tableRecord.getName());
				assertEquals(Long.MIN_VALUE, tableRecord.getMaxKey());
				assertEquals(0, tableRecord.getRecordCount());
				assertEquals(-1, tableRecord.getRootBufferId());
				++indexCnt;
			}

		}
		Schema schema = lastTable.getSchema();
		assertEquals(schema.getFields().length - 2, indexCnt); // ByteField and BooleanField do not support indexing
		assertEquals(totalTableCnt, tableCnt);

	}

	@Test
	public void testRemoveIndexedTables() throws IOException {
		removeIndexedTables(false);
	}

	@Test
	public void testStoredRemoveIndexedTables() throws IOException {
		removeIndexedTables(true);
	}

	@Test
	public void testLargeMasterTable() throws IOException {
		createNonIndexedTables(false, 1000);
	}

	@Test
	public void testStoredLargeMasterTable() throws IOException {
		createNonIndexedTables(true, 1000);
	}

	@Test
	public void testMasterTableUndo() throws IOException {
		createIndexedTables(false);
		Table[] tables = dbh.getTables();
		String table1Name = tables[1].getName();

		// delete a table - and rollback
		long txId = dbh.startTransaction();
		for (Table table : tables) {
			dbh.deleteTable(table.getName());
		}
		dbh.endTransaction(txId, false);

		assertTrue(dbh.getBufferMgr().atCheckpoint());

		try {
			tables[1].getName();
			Assert.fail();
		}
		catch (Exception e) {
			// Ignore
		}

		Schema s = tables[1].getSchema();
		DBRecord rec = s.createRecord(1);

		txId = dbh.startTransaction();
		try {
			tables[1].putRecord(rec);
			Assert.fail();
		}
		catch (Exception e) {
			// Ignore
		}
		assertTrue(dbh.getBufferMgr().atCheckpoint());

		Table t = dbh.getTable(table1Name);
		assertEquals(table1Name, t.getName());

		t.putRecord(rec);
		assertTrue(!dbh.getBufferMgr().atCheckpoint());
		dbh.endTransaction(txId, true);

		assertEquals(rec, t.getRecord(1));

		// delete a table - and commit
		txId = dbh.startTransaction();
		dbh.deleteTable(table1Name);
		dbh.endTransaction(txId, true);

		assertTrue(dbh.undo());

		t = dbh.getTable(table1Name);
		assertEquals(table1Name, t.getName());

		assertTrue(dbh.redo());

		t = dbh.getTable(table1Name);
		assertNull(t);

	}

	@Test
	public void testTableWithIndexRecreateUndo() throws IOException {

		createIndexedTables(false);

		Table[] tables = dbh.getTables();
		String table1Name = tables[1].getName();

		Table t1 = dbh.getTable(table1Name);
		int[] indexedColumns = t1.getIndexedColumns();
		assertEquals(t1.getSchema().getFieldCount(), indexedColumns.length);
		for (int i = 0; i < indexedColumns.length; i++) {
			assertEquals(i, indexedColumns[i]);
		}

		Schema schema = t1.getSchema();

		long txId = dbh.startTransaction();
		try {
			t1.putRecord(schema.createRecord(1));
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		txId = dbh.startTransaction();
		try {
			dbh.deleteTable(table1Name);
			dbh.createTable(table1Name, schema, indexedColumns);
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		dbh.undo();

		Table t1prime = dbh.getTable(table1Name);
		indexedColumns = t1prime.getIndexedColumns();
		assertEquals(t1prime.getSchema().getFieldCount(), indexedColumns.length);
		for (int i = 0; i < indexedColumns.length; i++) {
			assertEquals(i, indexedColumns[i]);
		}

		assertNotNull(t1prime.getRecord(1));

	}
}
