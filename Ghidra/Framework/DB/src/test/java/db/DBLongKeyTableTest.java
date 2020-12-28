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

public class DBLongKeyTableTest extends AbstractGenericTest {

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

	private long insertOneLongKeyRecord(boolean testStoredDB, boolean testGetRecord,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createLongKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false, false);
		DBRecord rec = null;
		try {
			rec = DBTestUtils.createLongKeyRecord(table, true, varDataSize, true);
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
			assertEquals(rec, table.getRecord(rec.getKey()));
		}
		return rec.getKey();
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertSmallLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, false, 1);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use empty value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertLongKeyRecordWithEmptyField() throws IOException {
		insertOneLongKeyRecord(false, false, 0);
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Use NULL value for variable length fields.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testInsertLongKeyRecordWithNullField() throws IOException {
		insertOneLongKeyRecord(false, false, -1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testInsertSingleChainedBufferLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, false, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertMultChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, false, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testInsertVeryLargeChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, false, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetSmallLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetSingleChainedBufferLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetMultChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetVeryLargeChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(false, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	/**
	 * Test normal record storage within a leaf node.
	 * Chained-buffers will not be utilized.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSmallLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(true, true, 1);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will not utilize an index buffer.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredSingleChainedBufferLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(true, true, BUFFER_SIZE / 4);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 1 buffer for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredMultChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(true, true, 2 * BUFFER_SIZE);
	}

	/**
	 * Test the use of chained-buffers for record storage.
	 * Chained-buffers will be forced to utilize 3 buffers for storing indexes.
	 * @throws IOException
	 */
	@Test
	public void testGetStoredVeryLargeChainedBuffersLongKeyRecord() throws IOException {
		insertOneLongKeyRecord(true, true, 2 * BUFFER_SIZE * (BUFFER_SIZE / 4));
	}

	@Test
	public void testGetMissingLongKeyRecord() throws IOException {
		long key = insertOneLongKeyRecord(false, false, 1);
		assertNull(dbh.getTable(table1Name).getRecord(key + 1));
	}

	@Test
	public void testStoredGetMissingLongKeyRecord() throws IOException {
		long key = insertOneLongKeyRecord(true, false, 1);
		assertNull(dbh.getTable(table1Name).getRecord(key + 1));
	}

	/**
	 * Insert the specified number of records using random keys.
	 * @param table table instance, if null one will be created
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createRandomLongKeyTableRecords(Table table, int recordCnt, int varDataSize)
			throws IOException {
		long txId = dbh.startTransaction();
		if (table == null) {
			table = DBTestUtils.createLongKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false,
				false);
		}
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] = DBTestUtils.createLongKeyRecord(table, true, varDataSize, true);
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
	private DBRecord[] createOrderedLongKeyTableRecords(int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createLongKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, false, false);
		long key = 0;
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] = DBTestUtils.createRecord(table, key, varDataSize, true);
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
	private void iterateLongKeyRecords(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomLongKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedLongKeyTableRecords(recordCnt, keyIncrement, varDataSize);
		}
		Arrays.sort(recs);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());
		assertEquals(recs[recordCnt - 1].getKey(), table.getMaxKey());

		// Forward iteration (no start)
		int recIx = 0;
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Forward iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKey());
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Reverse iteration (no start)
		recIx = recordCnt - 1;
		iter = table.iterator(Long.MAX_VALUE);
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(-1, recIx);

		// Reverse iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.iterator(recs[recIx].getKey());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(-1, recIx);

		// Range iteration (forward)
		int minIx = recordCnt / 10;
		int maxIx = 2 * minIx;
		iter = table.iterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[minIx].getKey());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
		}
		assertEquals(recIx, maxIx + 1);

		// Range iteration (reverse)
		iter = table.iterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[maxIx].getKey());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
		}
		assertEquals(recIx, minIx - 1);

		// Assumes consecutive keys do not exist - assumption could be a problem with random keys
		if (keyIncrement > 1 || keyIncrement < -1) {

			// Range iteration (forward) starting at min and not on existing record.
			long missingMinKey = recs[minIx].getKey() - 1;
			long missingMaxKey = recs[maxIx].getKey() + 1;
			iter = table.iterator(missingMinKey + 1, missingMaxKey, missingMinKey);
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
			iter = table.iterator(missingMinKey, missingMaxKey - 1, missingMaxKey);
			recIx = maxIx;
			assertTrue(!iter.hasNext());
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--], iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (reverse) starting at mid and not on existing record
			int midIx = (minIx + maxIx) >>> 1;
			long missingMidKey = recs[midIx].getKey() - 1;
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
		iter = table.iterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[minIx].getKey());
		recIx = minIx;
		while (iter.hasNext()) {
			iter.next();
			iter.delete();
			++recIx;
		}
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.iterator(recs[minIx - 1].getKey(), recs[maxIx + 1].getKey(),
			recs[minIx - 1].getKey());
		assertEquals(recs[minIx - 1], iter.next());
		assertEquals(recs[maxIx + 1], iter.next());

		// Range iteration (reverse)
		txId = dbh.startTransaction();
		minIx = minIx * 3;
		maxIx += minIx;
		iter = table.iterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[maxIx].getKey());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			iter.previous();
			iter.delete();
			--recIx;
		}
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.iterator(recs[minIx - 1].getKey(), recs[maxIx + 1].getKey(),
			recs[minIx - 1].getKey());
		assertEquals(recs[minIx - 1], iter.next());
		assertEquals(recs[maxIx + 1], iter.next());
	}

	@Test
	public void testLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testRandomLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, SMALL_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBackwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, SMALL_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testStoredLongKeyRandomRecordIterator() throws IOException {
		iterateLongKeyRecords(true, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testStoredForwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(true, SMALL_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testStoredBackwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(true, SMALL_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testBigRandomLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigForwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, BIG_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBigBackwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(false, BIG_ITER_REC_CNT, -2, 1);
	}

	@Test
	public void testBigStoredRandomLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(true, BIG_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testBigStoredForwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(true, BIG_ITER_REC_CNT, 2, 1);
	}

	@Test
	public void testBigStoredBackwardLongKeyRecordIterator() throws IOException {
		iterateLongKeyRecords(true, BIG_ITER_REC_CNT, -2, 1);
	}

	/**
	 * Test key iterator.
	 * @param testStoredDB test against a stored database if true, else test against cached database only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void iterateLongKeys(boolean testStoredDB, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomLongKeyTableRecords(null, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedLongKeyTableRecords(recordCnt, keyIncrement, varDataSize);
		}
		Arrays.sort(recs);
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());
		assertEquals(recs[recordCnt - 1].getKey(), table.getMaxKey());

		// Forward iteration (no start)
		int recIx = 0;
		DBLongIterator iter = table.longKeyIterator();
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKey(), iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Forward iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.longKeyIterator(recs[recIx].getKey());
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKey(), iter.next());
		}
		assertEquals(recordCnt, recIx);

		// Reverse iteration (no start)
		recIx = recordCnt - 1;
		iter = table.longKeyIterator(Long.MAX_VALUE);
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKey(), iter.previous());
		}
		assertEquals(-1, recIx);

		// Reverse iteration (start in middle)
		recIx = recordCnt / 2;
		iter = table.longKeyIterator(recs[recIx].getKey());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKey(), iter.previous());
		}
		assertEquals(-1, recIx);

		// Range iteration (forward) starting at min on existing record
		int minIx = recordCnt / 10;
		int maxIx = 2 * minIx;
		iter =
			table.longKeyIterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[minIx].getKey());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKey(), iter.next());
		}
		assertEquals(recIx, maxIx + 1);

		// Range iteration (reverse) starting at max on existing record
		iter =
			table.longKeyIterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[maxIx].getKey());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKey(), iter.previous());
		}
		assertEquals(recIx, minIx - 1);

		// Assumes consecutive keys do not exist - assumption could be a problem with random keys
		if (keyIncrement != 1) {

			// Range iteration (forward) starting at min and not on existing record.
			long missingMinKey = recs[minIx].getKey() - 1;
			long missingMaxKey = recs[maxIx].getKey() + 1;
			iter = table.longKeyIterator(missingMinKey, missingMaxKey, missingMinKey);
			recIx = minIx;
			assertTrue(!iter.hasPrevious());
			while (iter.hasNext()) {
				assertEquals(recs[recIx++].getKey(), iter.next());
			}
			assertEquals(recIx, maxIx + 1);

			// Range iteration - no records (forward and reverse).
			iter = table.longKeyIterator(missingMinKey, missingMinKey, missingMinKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());
			iter = table.longKeyIterator(missingMaxKey, missingMaxKey, missingMaxKey);
			assertTrue(!iter.hasNext());
			assertTrue(!iter.hasPrevious());

			// Range iteration (reverse) starting at max and not on existing record
			iter = table.longKeyIterator(missingMinKey, missingMaxKey, missingMaxKey);
			recIx = maxIx;
			assertTrue(!iter.hasNext());
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--].getKey(), iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (reverse) starting at mid and not on existing record
			int midIx = (minIx + maxIx) / 2;
			long missingMidKey = recs[midIx].getKey() - 1;
			iter = table.longKeyIterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx - 1;
			while (iter.hasPrevious()) {
				assertEquals(recs[recIx--].getKey(), iter.previous());
			}
			assertEquals(recIx, minIx - 1);

			// Range iteration (forward) starting at mid and not on existing record
			iter = table.longKeyIterator(missingMinKey, missingMaxKey, missingMidKey);
			recIx = midIx;
			while (iter.hasNext()) {
				assertEquals(recs[recIx++].getKey(), iter.next());
			}
			assertEquals(recIx, maxIx + 1);
		}

		// delete (forward)
		long txId = dbh.startTransaction();
		iter =
			table.longKeyIterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[minIx].getKey());
		recIx = minIx;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++].getKey(), iter.next());
			iter.delete();
		}
		assertEquals(recIx, maxIx + 1);
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.longKeyIterator(recs[minIx - 1].getKey(), recs[maxIx + 1].getKey(),
			recs[minIx - 1].getKey());
		assertEquals(recs[minIx - 1].getKey(), iter.next());
		assertEquals(recs[maxIx + 1].getKey(), iter.next());

		// Range iteration (reverse)
		txId = dbh.startTransaction();
		minIx = minIx * 3;
		maxIx += minIx;
		iter =
			table.longKeyIterator(recs[minIx].getKey(), recs[maxIx].getKey(), recs[maxIx].getKey());
		recIx = maxIx;
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--].getKey(), iter.previous());
			iter.delete();
		}
		assertEquals(recIx, minIx - 1);
		dbh.endTransaction(txId, true);

		recordCnt -= maxIx - minIx + 1;
		assertEquals(table.getRecordCount(), recordCnt);
		iter = table.longKeyIterator(recs[minIx - 1].getKey(), recs[maxIx + 1].getKey(),
			recs[minIx - 1].getKey());
		assertEquals(recs[minIx - 1].getKey(), iter.next());
		assertEquals(recs[maxIx + 1].getKey(), iter.next());
	}

	@Test
	public void testRandomLongKeyIterator() throws IOException {
		iterateLongKeys(false, SMALL_ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardLongKeyIterator() throws IOException {
		iterateLongKeys(false, SMALL_ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testForwardSkippingLongKeyIterator() throws IOException {
		iterateLongKeys(false, SMALL_ITER_REC_CNT, 3, 1);
	}

	@Test
	public void testForwardDeleteIterator() throws IOException {

		DBRecord[] recs = createOrderedLongKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);
		assertEquals(SMALL_ITER_REC_CNT, table.getRecordCount());
		assertEquals(recs[SMALL_ITER_REC_CNT - 1].getKey(), table.getMaxKey());

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

		DBRecord[] recs = createOrderedLongKeyTableRecords(SMALL_ITER_REC_CNT, 2, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);
		assertEquals(SMALL_ITER_REC_CNT, table.getRecordCount());
		assertEquals(recs[SMALL_ITER_REC_CNT - 1].getKey(), table.getMaxKey());

		long txId = dbh.startTransaction();
		int recIx = SMALL_ITER_REC_CNT - 1;
		RecordIterator iter = table.iterator(recs[recIx].getKey());
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
			iter.delete();
		}
		assertEquals(-1, recIx);
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testGetLongKeyRecordAfter() throws IOException {
		DBRecord[] recs = createRandomLongKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// After test
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAfter(recs[i].getKey());
			assertEquals(rec.getKey(), recs[i + 1].getKey());
		}

		// End test
		DBRecord rec = table.getRecordAfter(recs[15999].getKey());
		assertNull(rec);
	}

	private int findHoleAfterLongKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length - 1; i++) {
			if ((recs[i].getKey() + 1) < recs[i + 1].getKey()) {
				return i;
			}
		}
		return -1;
	}

	private int findHoleBeforeLongKey(DBRecord[] recs, int startIx) {
		for (int i = startIx; i < recs.length; i++) {
			if ((recs[i - 1].getKey() + 1) < recs[i].getKey()) {
				return i;
			}
		}
		return -1;
	}

	@Test
	public void testGetLongKeyRecordAtOrAfter() throws IOException {
		DBRecord[] recs = createRandomLongKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and After tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrAfter(recs[i].getKey());
			assertEquals(rec.getKey(), recs[i].getKey());
			int ix = findHoleAfterLongKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec = table.getRecordAtOrAfter(recs[ix].getKey() + 1);
			assertEquals(recs[ix + 1].getKey(), rec.getKey());
		}

		// End tests
		long lastKey = recs[15999].getKey();
		if (lastKey == Long.MAX_VALUE) {
			Assert.fail("Bad test data");
		}
		DBRecord rec = table.getRecordAtOrAfter(lastKey);
		assertEquals(rec.getKey(), lastKey);
		rec = table.getRecordAtOrAfter(lastKey + 1);
		assertNull(rec);
	}

	@Test
	public void testGetLongKeyRecordAtOrBefore() throws IOException {
		DBRecord[] recs = createRandomLongKeyTableRecords(null, 16000, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		// At and Before tests
		for (int i = 1000; i < 16000; i += 1000) {
			DBRecord rec = table.getRecordAtOrBefore(recs[i].getKey());
			assertEquals(rec.getKey(), recs[i].getKey());
			int ix = findHoleBeforeLongKey(recs, i + 500);
			if (ix < 0) {
				Assert.fail("Bad test data");
			}
			rec = table.getRecordAtOrBefore(recs[ix].getKey() - 1);
			assertEquals(recs[ix - 1].getKey(), rec.getKey());
		}

		// End tests
		long firstKey = recs[0].getKey();
		if (firstKey == Long.MIN_VALUE) {
			Assert.fail("Bad test data");
		}
		DBRecord rec = table.getRecordAtOrBefore(firstKey);
		assertEquals(rec.getKey(), firstKey);
		rec = table.getRecordAtOrBefore(firstKey - 1);
		assertNull(rec);
	}

	@Test
	public void testDeleteLongKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 1000) {
			table.deleteRecord(recs[i].getKey());
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
	public void testForwardDeleteLongKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		int count = cnt;
		for (int i = 0; i < count; i++) {
			table.deleteRecord(recs[i].getKey());
			assertEquals(--cnt, table.getRecordCount());
		}
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testReverseDeleteLongKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		long txId = dbh.startTransaction();
		for (int i = cnt - 1; i >= 0; i--) {
			table.deleteRecord(recs[i].getKey());
			assertEquals(--cnt, table.getRecordCount());
		}
		dbh.endTransaction(txId, true);
	}

	@Test
	public void testDeleteAllLongKeyRecords() throws IOException {

		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
		Arrays.sort(recs);

		long txId = dbh.startTransaction();
		Table table = dbh.getTable(table1Name);
		table.deleteAll();
		dbh.endTransaction(txId, true);

		assertEquals(0, table.getRecordCount());

		RecordIterator iter = table.iterator();
		assertTrue(!iter.hasNext());

		// Repopulate table
		recs = createRandomLongKeyTableRecords(table, cnt, 1);
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

	private void deleteLongKeyRangeRecords(int count, int startIx, int endIx) throws IOException {

		DBRecord[] recs = createRandomLongKeyTableRecords(null, count, 1);
		Arrays.sort(recs);

		long txId = dbh.startTransaction();
		Table table = dbh.getTable(table1Name);
		table.deleteRecords(recs[startIx].getKey(), recs[endIx].getKey());
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
	public void testDeleteLongKeyRangeRecords() throws IOException {
		deleteLongKeyRangeRecords(SMALL_ITER_REC_CNT, SMALL_ITER_REC_CNT / 4,
			SMALL_ITER_REC_CNT / 2);
	}

	@Test
	public void testDeleteLongKeyRangeRecords2() throws IOException {
		deleteLongKeyRangeRecords(SMALL_ITER_REC_CNT, (SMALL_ITER_REC_CNT / 4) + 1,
			(SMALL_ITER_REC_CNT / 2) + 1);
	}

	@Test
	public void testDeleteLongKeyRangeAllRecords() throws IOException {
		deleteLongKeyRangeRecords(SMALL_ITER_REC_CNT, 0, SMALL_ITER_REC_CNT - 1);
	}

	@Test
	public void testUpdateLongKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
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
	public void testUpdateBigLongKeyRecord() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;
		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);
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
	public void testUpdateUndoLongKeyRecords() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;

		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());

		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);

		Arrays.sort(recs);
		Table table = dbh.getTable(table1Name);

		assertTrue(dbh.canUndo());
		assertTrue(!dbh.canRedo());

		// Update records
		long txId = dbh.startTransaction();
		for (int i = 0; i < cnt; i += 100) {
			DBRecord rec = table.getSchema().createRecord(recs[i].getKey());
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
				DBTestUtils.createLongKeyRecord(table, true, BUFFER_SIZE, true);
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
	public void testUpdateUndoRedoLongKeyRecords() throws IOException {
		int cnt = SMALL_ITER_REC_CNT;

		assertTrue(!dbh.canUndo());
		assertTrue(!dbh.canRedo());

		DBRecord[] recs = createRandomLongKeyTableRecords(null, cnt, 1);

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
					DBTestUtils.createLongKeyRecord(table, true, BUFFER_SIZE, true);
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
