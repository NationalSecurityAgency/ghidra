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

public class DBFixedKeyTableTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;// keep small for chained buffer testing
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final int SMALL_ITER_REC_CNT = 16000;
	private static final int BIG_ITER_REC_CNT = 48000;

	private static final String table1Name = "TABLE1";

	private File testDir;
	private static final String dbName = "test";

	private BufferFileManager fileMgr;
	private DBHandle dbh;
	private BufferFile bfile;

	private static FixedField10 MAX_VALUE = new FixedField10();
	static {
		byte[] maxBytes = new byte[10];
		Arrays.fill(maxBytes, (byte) 0xff);
		MAX_VALUE.setBinaryData(maxBytes);
	}
	private static FixedField10 MIN_VALUE = new FixedField10(); // all zeros

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

	private FixedField10 insertOneFixedKeyRecord(boolean testStoredDB, boolean testGetRecord,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false, false);
		DBRecord rec = null;
		try {
			rec = DBTestUtils.createFixedKeyRecord(table, varDataSize, true);
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
		return (FixedField10) rec.getKeyField();
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertSmallFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, false, 1);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use empty value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertFixedKeyRecordWithEmptyField() throws IOException {
		insertOneFixedKeyRecord(false, false, 0);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use NULL value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertFixedKeyRecordWithNullField() throws IOException {
		insertOneFixedKeyRecord(false, false, -1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testInsertSingleChainedBufferFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, false, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertMultChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, false, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertVeryLargeChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, false, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetSmallFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetSingleChainedBufferFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetMultChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetVeryLargeChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(false, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSmallFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(true, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSingleChainedBufferFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(true, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredMultChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(true, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredVeryLargeChainedBuffersFixedKeyRecord() throws IOException {
		insertOneFixedKeyRecord(true, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	@Test
	public void testGetMissingFixedKeyRecord() throws IOException {
		FixedField10 key = insertOneFixedKeyRecord(false, false, 1);
		byte[] k = key.getBinaryData();
		++k[0];
		FixedField10 otherKey = new FixedField10(k); // incremented key
		assertNull(dbh.getTable(table1Name).getRecord(otherKey));
	}

	@Test
	public void testStoredGetMissingFixedKeyRecord() throws IOException {
		FixedField10 key = insertOneFixedKeyRecord(true, false, 1);
		byte[] k = key.getBinaryData();
		++k[0];
		FixedField10 otherKey = new FixedField10(k); // incremented key
		assertNull(dbh.getTable(table1Name).getRecord(otherKey));
	}

	/**
	 * Insert the specified number of records using random keys.
	 * @param table table instance, if null one will be created
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createRandomFixedKeyTableRecords(Table table, int recordCnt, int varDataSize)
			throws IOException {
		long txId = dbh.startTransaction();
		if (table == null) {
			table = DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false,
				false);
		}
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] = DBTestUtils.createFixedKeyRecord(table, varDataSize, true);
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
	private DBRecord[] createOrderedFixedKeyTableRecords(int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false, false);
		FixedField10 key = new FixedField10(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] = DBTestUtils.createRecord(table, key, varDataSize, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
			key = (FixedField10) DBTestUtils.addToFixedField(key, keyIncrement);
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
	private void iterateFixedKeyRecords(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomFixedKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedFixedKeyTableRecords(recordCnt, keyIncrement, varDataSize);
		}
		Arrays.sort(recs);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());
		//assertEquals(recs[recordCnt - 1].getKeyField(), table.getMaxKey());

		// Forward iteration (no start)
		int recIx = 0;
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Forward iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKeyField());
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Reverse iteration (no start)
		recIx = recordCnt - 1;
		iter = table.iterator(MAX_VALUE);
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(-1, recIx);

		// Reverse iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKeyField());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(-1, recIx);

		// Range iteration (forward)
		int minIx = recordCnt / 10;
		int maxIx = 2 * minIx;
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[minIx].getKeyField());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recIx, maxIx + 1);

		// Range iteration (reverse)
		iter = table.iterator(recs[minIx].getKeyField(), recs[maxIx].getKeyField(),
			recs[maxIx].getKeyField());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(recIx, minIx - 1);

		// Assumes consecutive keys do not exist - assumption could be a problem with random keys
		if (keyIncrement > 1 || keyIncrement < -1) {

			// Range iteration (forward) starting at min and not on existing record.
			FixedField missingMinKey = DBTestUtils.addToFixedField(recs[minIx].getKeyField(), -1);
			FixedField missingMaxKey = DBTestUtils.addToFixedField(recs[maxIx].getKeyField(), 1);
			iter = table.iterator(DBTestUtils.addToFixedField(missingMinKey, 1), missingMaxKey,
				missingMinKey);
			recIx = minIx;
			assertTrue(!iter.hasPrevious());
			while (iter.hasNext()) {
				assertEquals(recs[recIx++], iter.next());
			}
			assertEquals(recIx, maxIx + 1);

			// Range iteration - no records (forward and reverse).
			iter = table.iterator(missingMinKey, missingMinKey, missingMinKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());
			iter = table.iterator(missingMaxKey, missingMaxKey, missingMaxKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());

			// Range iteration (reverse) starting at max and not on existing record
			iter = table.iterator(missingMinKey, DBTestUtils.addToFixedField(missingMaxKey, -1),
				missingMaxKey);
			recIx = maxIx;
			assertTrue(!iter.hasNext());
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--], iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (reverse) starting at mid and not on existing record
			int midIx = (minIx + maxIx) >>> 1;
			FixedField missingMidKey = DBTestUtils.addToFixedField(recs[midIx].getKeyField(), -1);
			iter = table.iterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx - 1;
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--], iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (forward) starting at mid and not on existing record
			iter = table.iterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx;
			while (iter.hasNext()) {
				assertEquals(recs[recIx++], iter.next());
			}
			assertEquals(recIx, maxIx + 1);
		}

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
	public void testFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testRandomFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, SMALL_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBackwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, SMALL_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testStoredFixedKeyRandomRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testStoredForwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, SMALL_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testStoredBackwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, SMALL_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testBigRandomFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigForwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, BIG_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBigBackwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(false, BIG_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testBigStoredRandomFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigStoredForwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, BIG_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBigStoredBackwardFixedKeyRecordIterator() throws IOException {
		iterateFixedKeyRecords(true, BIG_ITER_REC_CNT, -2, 1);
	}

	/**
	 * Test key iterator.
	 * @param testStoredDB test against a stored database if true, else test against cached database only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void iterateFixedKeys(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomFixedKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedFixedKeyTableRecords(recordCnt, keyIncrement, varDataSize);
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
		iter = table.fieldKeyIterator(MAX_VALUE);
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
			FixedField missingMinKey = DBTestUtils.addToFixedField(recs[minIx].getKeyField(), -1);
			FixedField missingMaxKey = DBTestUtils.addToFixedField(recs[maxIx].getKeyField(), 1);
			iter = table.fieldKeyIterator(missingMinKey, missingMaxKey, missingMinKey);
			recIx = minIx;
			assertTrue(!iter.hasPrevious());
			while (iter.hasNext()) {
				assertEquals(recs[recIx++].getKeyField(), iter.next());
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
			assertTrue(!iter.hasNext());
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--].getKeyField(), iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (reverse) starting at mid and not on existing record
			int midIx = (minIx + maxIx) / 2;
			FixedField missingMidKey = DBTestUtils.addToFixedField(recs[midIx].getKeyField(), -1);
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
	public void testRandomFixedKeyIterator() throws IOException {
		iterateFixedKeys(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardFixedKeyIterator() throws IOException {
		iterateFixedKeys(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testForwardSkippingFixedKeyIterator() throws IOException {
		iterateFixedKeys(false, SMALL_ITER_REC_CNT, 3, 1);
	}

	@Test
	public void testForwardDeleteIterator() throws IOException {

		DBRecord[] recs = createOrderedFixedKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
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

		DBRecord[] recs = createOrderedFixedKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
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
	public void testGetFixedKeyRecordAfter() throws IOException {
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, 16000, 1);
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

	private int findHoleAfterFixedKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length - 1; i++) {
			FixedField f = DBTestUtils.addToFixedField(recs[i].getKeyField(), 1);
			if (f.compareTo(recs[i + 1].getKeyField()) < 0) {
				return i;
			}
		}
		return -1;
	}

	private int findHoleBeforeFixedKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length; i++) {
			FixedField f = DBTestUtils.addToFixedField(recs[i - 1].getKeyField(), 1);
			if (f.compareTo(recs[i].getKeyField()) < 0) {
				return i;
			}
		}
		return -1;
	}

	@Test
	public void testGetFixedKeyRecordAtOrAfter() throws IOException {
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and After tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrAfter(recs[i].getKeyField());
			assertEquals(rec.getKeyField(), recs[i].getKeyField());
			int ix = findHoleAfterFixedKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec = table.getRecordAtOrAfter(DBTestUtils.addToFixedField(recs[ix].getKeyField(), 1));
			assertEquals(recs[ix + 1].getKeyField(), rec.getKeyField());
		}

		// End tests
		Field lastKey = recs[15999].getKeyField();
		if (lastKey == MAX_VALUE) {
			Assert.fail("Bad test data");
		}
		DBRecord rec = table.getRecordAtOrAfter(lastKey);
		assertEquals(rec.getKeyField(), lastKey);
		rec = table.getRecordAtOrAfter(DBTestUtils.addToFixedField(lastKey, 1));
		assertNull(rec);
	}

	@Test
	public void testGetFixedKeyRecordAtOrBefore() throws IOException {
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and Before tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrBefore(recs[i].getKeyField());
			assertEquals(rec.getKeyField(), recs[i].getKeyField());
			int ix = findHoleBeforeFixedKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec =
				table.getRecordAtOrBefore(DBTestUtils.addToFixedField(recs[ix].getKeyField(), -1));
			assertEquals(recs[ix - 1].getKeyField(), rec.getKeyField());
		}

		// End tests
		Field firstKey = recs[0].getKeyField();
		if (firstKey.equals(MIN_VALUE)) {
			Assert.fail("Bad test data");
		}
		DBRecord rec = table.getRecordAtOrBefore(firstKey);
		assertEquals(rec.getKeyField(), firstKey);
		rec = table.getRecordAtOrBefore(DBTestUtils.addToFixedField(firstKey, -1));
		assertNull(rec);
	}

	@Test
	public void testDeleteFixedKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
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
	public void testForwardDeleteFixedKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
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
	public void testReverseDeleteFixedKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
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
	public void testDeleteAllFixedKeyRecords() throws IOException {

		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);

		long txId = dbh.startTransaction();
		Table table = dbh.getTable(table1Name);
		table.deleteAll();
		dbh.endTransaction(txId, true);

		assertEquals(0, table.getRecordCount());

		RecordIterator iter = table.iterator();
		assertTrue(!iter.hasNext());

		// Repopulate table
		recs = createRandomFixedKeyTableRecords(table, cnt, 1);
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

	private void deleteFixedKeyRangeRecords(int count, int startIx, int endIx) throws IOException {

		DBRecord[] recs = createRandomFixedKeyTableRecords(null, count, 1);
		Arrays.sort(recs);

		long txId = dbh.startTransaction();
		Table table = dbh.getTable(table1Name);
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
	public void testDeleteFixedKeyRangeRecords() throws IOException {
		deleteFixedKeyRangeRecords(SMALL_ITER_REC_CNT, SMALL_ITER_REC_CNT / 4,
			SMALL_ITER_REC_CNT / 2);
	}

	@Test
	public void testDeleteFixedKeyRangeRecords2() throws IOException {
		deleteFixedKeyRangeRecords(SMALL_ITER_REC_CNT, (SMALL_ITER_REC_CNT / 4) + 1,
			(SMALL_ITER_REC_CNT / 2) + 1);
	}

	@Test
	public void testDeleteFixedKeyRangeAllRecords() throws IOException {
		deleteFixedKeyRangeRecords(SMALL_ITER_REC_CNT, 0, SMALL_ITER_REC_CNT - 1);
	}

	@Test
	public void testUpdateFixedKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
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
	public void testUpdateBigFixedKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);
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

	@Test
	public void testUpdateUndoFixedKeyRecords() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;

		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());
		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);

		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		// Update records
		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBRecord rec = table.getSchema().createRecord(recs[i].getKeyField());
			DBTestUtils.fillRecord(rec, (BUFFER_SIZE / 8) * BUFFER_SIZE);
			table.putRecord(rec);
		}
		assertEquals(cnt, table.getRecordCount());
		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());

		dbh.endTransaction(txId, false);// rollback updates

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		RecordIterator iter = table.iterator();
		int recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);

		// Add records
		txId = dbh.startTransaction();
		for (int i = 0; i < 100; i++) {
			try {
				DBTestUtils.createFixedKeyRecord(table, BUFFER_SIZE, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
		}
		dbh.endTransaction(txId, true);

		assertTrue(dbh.undo());

		iter = table.iterator();
		recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);
	}

	@Test
	public void testUpdateUndoRedoFixedKeyRecords() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;

		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());

		DBRecord[] recs = createRandomFixedKeyTableRecords(null, cnt, 1);

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// Update records
		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBTestUtils.fillRecord(recs[i], (BUFFER_SIZE / 8) * BUFFER_SIZE);
			table.putRecord(recs[i]);
		}
		assertEquals(cnt, table.getRecordCount());
		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());
		dbh.endTransaction(txId, true);

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		assertTrue(dbh.undo());

		assertTrue(dbh.canUndo());
		assertTrue(dbh.canRedo());

		assertTrue(dbh.redo());

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		RecordIterator iter = table.iterator();
		int recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(cnt, recIx);

		// Add records
		DBRecord[] newRecs = new DBRecord[recs.length + 100];
		System.arraycopy(recs, 0, newRecs, 0, recs.length);
		txId = dbh.startTransaction();
		for (int i = 0; i < 100; i++) {
			try {
				newRecs[i + recs.length] =
					DBTestUtils.createFixedKeyRecord(table, BUFFER_SIZE, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
		}
		dbh.endTransaction(txId, true);

		recs = newRecs;
		Arrays.sort(recs);

		assertTrue(dbh.undo());

		assertTrue(dbh.redo());

		iter = table.iterator();
		recIx = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			assertEquals(recs[recIx++], rec);
		}
		assertEquals(recs.length, recIx);
	}

}
