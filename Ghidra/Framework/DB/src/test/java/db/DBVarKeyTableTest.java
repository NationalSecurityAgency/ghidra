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
import utilities.util.FileUtilities;

public class DBVarKeyTableTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;// keep small for chained buffer testing
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final int SMALL_ITER_REC_CNT = 8000;
	private static final int BIG_ITER_REC_CNT = 48000;

	private static final int MAX_VAR_KEY_LENGTH = 18;

	private static final String table1Name = "TABLE1";

	private File testDir;
	private static final String dbName = "test";

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

	private Field insertOneVarKeyRecord(boolean testStoredDB, boolean testGetRecord,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createBinaryKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false);
		DBRecord rec = null;
		try {
			rec = DBTestUtils.createBinaryKeyRecord(table, -MAX_VAR_KEY_LENGTH, varDataSize, true);
		}
		catch (DuplicateKeyException e) {
			Assert.fail("Duplicate key error");
		}
		dbh.endTransaction(txId, true);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
			table = dbh.getTable(table1Name);
		}
		if (testGetRecord) {
			assertEquals(rec, table.getRecord(rec.getKeyField()));
		}
		return rec.getKeyField();
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertSmallVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, false, 1);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use empty value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertVarKeyRecordWithEmptyField() throws IOException {
		insertOneVarKeyRecord(false, false, 0);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use NULL value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertVarKeyRecordWithNullField() throws IOException {
		insertOneVarKeyRecord(false, false, -1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testInsertSingleChainedBufferVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, false, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertMultChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, false, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertVeryLargeChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, false, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetSmallVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetSingleChainedBufferVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetMultChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetVeryLargeChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(false, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSmallVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(true, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSingleChainedBufferVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(true, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredMultChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(true, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredVeryLargeChainedBuffersVarKeyRecord() throws IOException {
		insertOneVarKeyRecord(true, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	@Test
	public void testGetMissingVarKeyRecord() throws IOException {
		Field key = insertOneVarKeyRecord(false, false, 1);
		byte[] bytes = key.getBinaryData();
		++bytes[0];
		key.setBinaryData(bytes);
		assertNull(dbh.getTable(table1Name).getRecord(key));
	}

	@Test
	public void testStoredGetMissingVarKeyRecord() throws IOException {
		Field key = insertOneVarKeyRecord(true, false, 1);
		byte[] bytes = key.getBinaryData();
		++bytes[0];
		key.setBinaryData(bytes);
		assertNull(dbh.getTable(table1Name).getRecord(key));
	}

	/**
	 * Insert the specified number of records using random keys.
	 * @param table table instance, if null one will be created
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createRandomVarKeyTableRecords(Table table, int recordCnt, int varDataSize)
			throws IOException {
		long txId = dbh.startTransaction();
		if (table == null) {
			table = DBTestUtils.createBinaryKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false);
		}
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] =
					DBTestUtils.createBinaryKeyRecord(table, MAX_VAR_KEY_LENGTH, varDataSize, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
		}
		dbh.endTransaction(txId, true);
		return recs;
	}

	/**
	 * Insert the specified number of records using random keys.
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createOrderedVarKeyTableRecords(int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createBinaryKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false);
		long key = 0;
		Field keyField = new LongField();

		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				keyField.setLongValue(key);
				recs[i] = DBTestUtils.createRecord(table, new BinaryField(keyField.getBinaryData()),
					varDataSize, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
			key += keyIncrement;
		}
		dbh.endTransaction(txId, true);
		return recs;
	}

	/**
	 * Test record iterator.
	 * @param testStoredDB test against a stored database if true, else test against cached database only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void iterateVarKeyRecords(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomVarKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedVarKeyTableRecords(recordCnt, keyIncrement, varDataSize);
		}
		Arrays.sort(recs);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());

		// Forward iteration (no start)
		int recIx = 0;
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(recordCnt, recIx);

		// Forward iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKeyField());
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(recordCnt, recIx);

		// Reverse iteration (no start)
		recIx = recordCnt - 1;
		iter = table.iterator(DBTestUtils.getMaxValue(MAX_VAR_KEY_LENGTH));
		while (iter.hasPrevious()) {
			DBRecord rec = iter.previous();
			assertEquals(recs[recIx--], rec);
		}
		assertEquals(-1, recIx);

		// Reverse iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKeyField());
		while (iter.hasPrevious()) {
			DBRecord rec = iter.previous();
			assertEquals(recs[recIx--], rec);
		}
		assertEquals(-1, recIx);

		// Range iteration (forward)
		int minIx = recordCnt / 10;
		int maxIx = 2 * minIx;
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[minIx].getKeyField());
		recIx = minIx;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(recIx, maxIx + 1);

		// Range iteration (reverse)
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[maxIx].getKeyField());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			DBRecord rec = iter.previous();
			assertEquals(recs[recIx--], rec);
		}
		assertEquals(recIx, minIx - 1);

		// delete (forward)
		long txId = dbh.startTransaction();
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[minIx].getKeyField());
		recIx = minIx;
		while (iter.hasNext()) {
			iter.next();
			iter.delete();
			++recIx;
		}
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.iterator(recs[minIx - 1].getKeyField(), recs[maxIx + 1].getKeyField(),
			recs[minIx - 1].getKeyField());
		assertEquals(recs[minIx - 1], iter.next());
		assertEquals(recs[maxIx + 1], iter.next());

		// Range iteration (reverse)
		txId = dbh.startTransaction();
		minIx = minIx * 3;
		maxIx += minIx;
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[maxIx].getKeyField());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			iter.previous();
			iter.delete();
			--recIx;
		}
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.iterator(recs[minIx - 1].getKeyField(), recs[maxIx + 1].getKeyField(),
			recs[minIx - 1].getKeyField());
		assertEquals(recs[minIx - 1], iter.next());
		assertEquals(recs[maxIx + 1], iter.next());

	}

	@Test
	public void testRandomVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testBackwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, SMALL_ITER_REC_CNT, -1, 1);
	}

	@Test
	public void testStoredVarKeyRandomRecordIterator() throws IOException {
		iterateVarKeyRecords(true, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testStoredForwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(true, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testStoredBackwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(true, SMALL_ITER_REC_CNT, -1, 1);
	}

	@Test
	public void testBigRandomVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigForwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, BIG_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testBigBackwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(false, BIG_ITER_REC_CNT, -1, 1);
	}

	@Test
	public void testBigStoredRandomVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(true, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigStoredForwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(true, BIG_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testBigStoredBackwardVarKeyRecordIterator() throws IOException {
		iterateVarKeyRecords(true, BIG_ITER_REC_CNT, -1, 1);
	}

	/**
	 * Test key iterator.
	 * @param testStoredDB test against a stored database if true, else test against cached database only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void iterateVarKeys(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomVarKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedVarKeyTableRecords(recordCnt, keyIncrement, varDataSize);
		}
		Arrays.sort(recs);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());

		// Forward iteration (no start)
		int recIx = 0;
		DBFieldIterator iter = table.fieldKeyIterator();
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKeyField(), iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Forward iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.fieldKeyIterator(recs[recIx].getKeyField());
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKeyField(), iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Reverse iteration (no start)
		recIx = recordCnt - 1;
		iter = table.fieldKeyIterator(DBTestUtils.getMaxValue(MAX_VAR_KEY_LENGTH));
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKeyField(), iter.previous());
		}
		assertEquals(-1, recIx);

		// Reverse iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.fieldKeyIterator(recs[recIx].getKeyField());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKeyField(), iter.previous());
		}
		assertEquals(-1, recIx);

		// Range iteration (forward) starting at min on existing record
		int minIx = recordCnt / 10;
		int maxIx = 2 * minIx;
		iter = table.fieldKeyIterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[minIx].getKeyField());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKeyField(), iter.next());
		}
		assertEquals(recIx, maxIx + 1);

		// Range iteration (reverse) starting at max on existing record
		iter = table.fieldKeyIterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[maxIx].getKeyField());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKeyField(), iter.previous());
		}
		assertEquals(recIx, minIx - 1);

		// Assumes consecutive keys do not exist - assumption could be a problem with random keys
		if (keyIncrement != 1) {

			// Range iteration (forward) starting at min and not on existing record.
			BinaryField dataMin = (BinaryField) recs[minIx].getKeyField();
			BinaryField dataMax = (BinaryField) recs[maxIx].getKeyField();
			BinaryField missingMinKey = DBTestUtils.decrement(dataMin, MAX_VAR_KEY_LENGTH);
			BinaryField missingMaxKey = DBTestUtils.increment(dataMax, MAX_VAR_KEY_LENGTH);
			iter = table.fieldKeyIterator(missingMinKey, missingMaxKey, missingMinKey);
			recIx = minIx;
			while (iter.hasNext()) {
				Field f = iter.next();
				assertEquals(recs[recIx++].getKeyField(), f);
			}
			assertEquals(recIx, maxIx + 1);

			// Range iteration - no records (forward and reverse).
			iter = table.fieldKeyIterator(missingMinKey, missingMinKey, missingMinKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());
			iter = table.fieldKeyIterator(missingMaxKey, missingMaxKey, missingMaxKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());

			// Range iteration (reverse) starting at max and not on existing record
			iter = table.fieldKeyIterator(missingMinKey, missingMaxKey, missingMaxKey);
			recIx = maxIx;
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--].getKeyField(), iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (reverse) starting at mid and not on existing record
			int midIx = (minIx + maxIx) / 2;
			BinaryField dataMid = (BinaryField) recs[midIx].getKeyField();
			BinaryField missingMidKey = DBTestUtils.decrement(dataMid, MAX_VAR_KEY_LENGTH);
			iter = table.fieldKeyIterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx - 1;
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--].getKeyField(), iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (forward) starting at mid and not on existing record
			iter = table.fieldKeyIterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx;
			while (iter.hasNext()) {
				assertEquals(recs[recIx++].getKeyField(), iter.next());
			}
			assertEquals(recIx, maxIx + 1);
		}

		// delete (forward)
		long txId = dbh.startTransaction();
		iter = table.fieldKeyIterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[minIx].getKeyField());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKeyField(), iter.next());
			iter.delete();
		}
		assertEquals(recIx, maxIx + 1);
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.fieldKeyIterator(recs[minIx - 1].getKeyField(), recs[maxIx + 1].getKeyField(),
			recs[minIx - 1].getKeyField());
		assertEquals(recs[minIx - 1].getKeyField(), iter.next());
		assertEquals(recs[maxIx + 1].getKeyField(), iter.next());

		// Range iteration (reverse)
		txId = dbh.startTransaction();
		minIx = minIx * 3;
		maxIx += minIx;
		iter = table.fieldKeyIterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[maxIx].getKeyField());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKeyField(), iter.previous());
			iter.delete();
		}
		assertEquals(recIx, minIx - 1);
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.fieldKeyIterator(recs[minIx - 1].getKeyField(), recs[maxIx + 1].getKeyField(),
			recs[minIx - 1].getKeyField());
		assertEquals(recs[minIx - 1].getKeyField(), iter.next());
		assertEquals(recs[maxIx + 1].getKeyField(), iter.next());
	}

	@Test
	public void testRandomVarKeyIterator() throws IOException {
		iterateVarKeys(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardVarKeyIterator() throws IOException {
		iterateVarKeys(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testForwardSkippingVarKeyIterator() throws IOException {
		iterateVarKeys(false, SMALL_ITER_REC_CNT, 3, 1);
	}

	@Test
	public void testForwardDeleteIterator() throws IOException {

		DBRecord[] recs = createOrderedVarKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);
		assertEquals(SMALL_ITER_REC_CNT, table.getRecordCount());

		int recIx = 0;
		long txId = dbh.startTransaction();
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
			iter.delete();
		}
		assertEquals(SMALL_ITER_REC_CNT, recIx);
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testReverseDeleteIterator() throws IOException {

		DBRecord[] recs = createOrderedVarKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);
		assertEquals(SMALL_ITER_REC_CNT, table.getRecordCount());

		long txId = dbh.startTransaction();
		int recIx = SMALL_ITER_REC_CNT - 1;
		RecordIterator iter = table.iterator(recs[recIx].getKeyField());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
			iter.delete();
		}
		assertEquals(-1, recIx);
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testGetVarKeyRecordAfter() throws IOException {
		DBRecord[] recs = createRandomVarKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// After test
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAfter(recs[i].getKeyField());
			assertEquals(rec.getKeyField(), recs[i + 1].getKeyField());
		}

		// End test
		DBRecord rec = table.getRecordAfter(recs[15999].getKeyField());
		assertNull(rec);
	}

	private int findHoleAfterVarKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length - 1; i++) {
			if (DBTestUtils.increment((BinaryField) recs[i].getKeyField(),
				MAX_VAR_KEY_LENGTH).compareTo(recs[i + 1].getKeyField()) < 0) {
				return i;
			}
		}
		return -1;
	}

	private int findHoleBeforeVarKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length; i++) {
			if (DBTestUtils.increment((BinaryField) recs[i - 1].getKeyField(),
				MAX_VAR_KEY_LENGTH).compareTo(recs[i].getKeyField()) < 0) {
				return i;
			}
		}
		return -1;
	}

	@Test
	public void testGetVarKeyRecordAtOrAfter() throws IOException {
		DBRecord[] recs = createRandomVarKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and After tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrAfter(recs[i].getKeyField());
			assertEquals(rec.getKeyField(), recs[i].getKeyField());
			int ix = findHoleAfterVarKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec = table.getRecordAtOrAfter(
				DBTestUtils.increment((BinaryField) recs[ix].getKeyField(), MAX_VAR_KEY_LENGTH));
			assertEquals(recs[ix + 1].getKeyField(), rec.getKeyField());
		}

		// End tests
		Field lastKey = recs[15999].getKeyField();
		DBRecord rec = table.getRecordAtOrAfter(lastKey);
		assertEquals(rec.getKeyField(), lastKey);
		rec = table.getRecordAtOrAfter(
			DBTestUtils.increment((BinaryField) lastKey, MAX_VAR_KEY_LENGTH));
		assertNull(rec);
	}

	@Test
	public void testGetVarKeyRecordAtOrBefore() throws IOException {
		DBRecord[] recs = createRandomVarKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and Before tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrBefore(recs[i].getKeyField());
			assertEquals(rec.getKeyField(), recs[i].getKeyField());
			int ix = findHoleBeforeVarKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec = table.getRecordAtOrBefore(
				DBTestUtils.decrement((BinaryField) recs[ix].getKeyField(), MAX_VAR_KEY_LENGTH));
			assertEquals(recs[ix - 1].getKeyField(), rec.getKeyField());
		}

		// End tests
		Field firstKey = recs[0].getKeyField();
		DBRecord rec = table.getRecordAtOrBefore(firstKey);
		assertEquals(rec.getKeyField(), firstKey);
		rec = table.getRecordAtOrBefore(
			DBTestUtils.decrement((BinaryField) firstKey, MAX_VAR_KEY_LENGTH));
		assertNull(rec);
	}

	@Test
	public void testDeleteVarKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 1000) {
			table.deleteRecord(recs[i].getKeyField());
			assertEquals(--cnt, table.getRecordCount());
		}
		dbh.endTransaction(txId, true);

		RecordIterator iter = table.iterator();
		int recIx = 1;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
			if ((recIx % 1000) == 0) {
				++recIx;
			}
		}
		assertEquals(SMALL_ITER_REC_CNT + 1, recIx);
	}

	@Test
	public void testForwardDeleteVarKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		int count = cnt;
		for (int i = 0; i < count; i++) {
			table.deleteRecord(recs[i].getKeyField());
			assertEquals(--cnt, table.getRecordCount());
		}
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testReverseDeleteVarKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = cnt - 1; i >= 0; i--) {
			table.deleteRecord(recs[i].getKeyField());
			assertEquals(--cnt, table.getRecordCount());
		}
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testDeleteAllVarKeyRecords() throws IOException {

		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		table.deleteAll();
		dbh.endTransaction(txId, true);

		assertEquals(0, table.getRecordCount());

		RecordIterator iter = table.iterator();
		assertTrue(!iter.hasNext());

		// Repopulate table
		recs = createRandomVarKeyTableRecords(table, cnt, 1);
		assertEquals(cnt, table.getRecordCount());
		Arrays.sort(recs);
		iter = table.iterator();
		int recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);
	}

	private void deleteVarKeyRangeRecords(int count, int startIx, int endIx) throws IOException {

		DBRecord[] recs = createRandomVarKeyTableRecords(null, count, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		table.deleteRecords(recs[startIx].getKeyField(), recs[endIx].getKeyField());
		dbh.endTransaction(txId, true);

		RecordIterator iter = table.iterator();
		int recIx = startIx != 0 ? 0 : (endIx + 1);
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
			if (recIx == startIx) {
				recIx = endIx + 1;
			}
		}
		assertEquals(recIx, count);
	}

	@Test
	public void testDeleteVarKeyRangeRecords() throws IOException {
		deleteVarKeyRangeRecords(SMALL_ITER_REC_CNT, SMALL_ITER_REC_CNT / 4,
			SMALL_ITER_REC_CNT / 2);
	}

	@Test
	public void testDeleteVarKeyRangeAllRecords() throws IOException {
		deleteVarKeyRangeRecords(SMALL_ITER_REC_CNT, 0, SMALL_ITER_REC_CNT - 1);
	}

	@Test
	public void testUpdateVarKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
//Record[] recs = createOrderedVarKeyTableRecords(cnt, 1, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBTestUtils.fillRecord(recs[i], BUFFER_SIZE);
			table.putRecord(recs[i]);
		}
		dbh.endTransaction(txId, true);

		RecordIterator iter = table.iterator();
		int recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);
	}

	@Test
	public void testUpdateBigVarKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomVarKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBTestUtils.fillRecord(recs[i], (BUFFER_SIZE / 8) * BUFFER_SIZE);
			table.putRecord(recs[i]);
		}
		dbh.endTransaction(txId, true);

		RecordIterator iter = table.iterator();
		int recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);

		txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBTestUtils.fillRecord(recs[i], 1);
			table.putRecord(recs[i]);
		}
		dbh.endTransaction(txId, true);

		iter = table.iterator();
		recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);
	}

}
