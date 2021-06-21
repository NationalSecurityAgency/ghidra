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
import java.util.*;

import org.junit.*;

import db.buffers.*;
import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

public class DBFixedKeyIndexedTableTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 2048;// keep small for chained buffer testing
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final int ITER_REC_CNT = 1000;

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

	/**
	 * Insert the specified number of records using random keys.
	 * 
	 * @param table table instance, if null one will be created
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createRandomTableRecords(int schemaType, int recordCnt, int varDataSize)
			throws IOException {
		long txId = dbh.startTransaction();
		Table table = DBTestUtils.createFixedKeyTable(dbh, table1Name, schemaType, true, false);
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
	 * 
	 * @param recordCnt number of records to insert.
	 * @param varDataSize size of variable length data fields.
	 * @return Record[] records which were inserted.
	 */
	private DBRecord[] createOrderedTableRecords(int schemaType, int recordCnt, long keyIncrement,
			int varDataSize) throws IOException {
		long txId = dbh.startTransaction();
		Table table = DBTestUtils.createFixedKeyTable(dbh, table1Name, schemaType, true, false);
		FixedField key = new FixedField10(new byte[] { 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff });
		DBRecord[] recs = new DBRecord[recordCnt];
		for (int i = 0; i < recordCnt; i++) {
			try {
				recs[i] = DBTestUtils.createRecord(table, key, varDataSize, true);
			}
			catch (DuplicateKeyException e) {
				Assert.fail("Duplicate key error");
			}
			key = DBTestUtils.addToFixedField(key, keyIncrement);
		}
		dbh.endTransaction(txId, true);
		return recs;
	}

	private Field[] matchingKeys(DBRecord[] recs, int columnIx, DBRecord matchRec) {
		ArrayList<DBRecord> recList = new ArrayList<>();
		Field f = matchRec.getField(columnIx);
		for (DBRecord rec : recs) {
			if (f.equals(rec.getField(columnIx))) {
				recList.add(rec);
			}
		}
		Field[] keys = new FixedField[recList.size()];
		Iterator<DBRecord> iter = recList.iterator();
		int i = 0;
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			keys[i++] = rec.getKeyField();
		}
		Arrays.sort(keys);
		return keys;
	}

	private void findRecords(boolean testStoredDB, int recordCnt, int findCnt, int varDataSize)
			throws IOException {
		DBRecord[] recs = createRandomTableRecords(DBTestUtils.ALL_TYPES, recordCnt, varDataSize);// short var-len fields
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		int[] indexedColumns = table.getIndexedColumns();
		int step = recordCnt / findCnt;
		for (int indexColumn : indexedColumns) {
			for (int i = 0; i < recordCnt; i += step) {
				Field[] keys = table.findRecords(recs[i].getField(indexColumn), indexColumn);
				Arrays.sort(keys);
				assertTrue(Arrays.equals(matchingKeys(recs, indexColumn, recs[i]), keys));
				assertEquals(keys.length,
					table.getMatchingRecordCount(recs[i].getField(indexColumn), indexColumn));
			}
		}
	}

	@Test
	public void testEmptyFixedKeyIterator() throws IOException {
		createRandomTableRecords(DBTestUtils.ALL_TYPES, 0, 1);

		dbh.undo();
		dbh.redo();

		saveAsAndReopen(dbName);

		Table table = dbh.getTable(table1Name);
		assertEquals(0, table.getRecordCount());

		Field startKey = new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 2, 0 });
		Field minKey = new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, 0 });
		Field maxKey = new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 3, 0 });
		DBFieldIterator iter = table.fieldKeyIterator();
		assertTrue(!iter.hasPrevious());
		assertTrue(!iter.hasNext());

		iter = table.fieldKeyIterator(startKey);
		assertTrue(!iter.hasPrevious());
		assertTrue(!iter.hasNext());

		iter = table.fieldKeyIterator(minKey, maxKey, startKey);
		assertTrue(!iter.hasPrevious());
		assertTrue(!iter.hasNext());

		startKey = FixedField10.INSTANCE.getMinValue();
		iter = table.fieldKeyIterator(minKey, maxKey, startKey);
		assertTrue(!iter.hasPrevious());
		assertTrue(!iter.hasNext());

		startKey = FixedField10.INSTANCE.getMaxValue();
		iter = table.fieldKeyIterator(minKey, maxKey, startKey);
		assertTrue(!iter.hasPrevious());
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testFindRecordsSmallVLR() throws IOException {
		findRecords(false, 1000, 100, 8);
	}

	@Test
	public void testFindRecordsBigVLR() throws IOException {
		findRecords(false, 1000, 100, 16);
	}

	@Test
	public void testFindStoredRecordsSmallVLR() throws IOException {
		findRecords(true, 1000, 100, 8);
	}

	@Test
	public void testFindStoredRecordsEmptyVLR() throws IOException {
		findRecords(true, 1000, 100, 0);
	}

	@Test
	public void testFindStoredRecordsNullVLR() throws IOException {
		findRecords(true, 1000, 100, -1);
	}

	@Test
	public void testFindStoredRecordsBigVLR() throws IOException {
		findRecords(true, 1000, 100, 16);
	}

	private void updateRecordsIterator(boolean testStoredDB, int schemaType, int recordCnt,
			long keyIncrement, int varDataSize) throws IOException {
		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomTableRecords(schemaType, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(schemaType, recordCnt, keyIncrement, varDataSize);
		}
		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);

		// Find string and binary columns
		int strColumn = -1;
		int binColumn = -1;
		Field[] fields = table.getSchema().getFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i].isSameType(StringField.INSTANCE)) {
				strColumn = i;
			}
			else if (fields[i].isSameType(BinaryField.INSTANCE)) {
				binColumn = i;
			}
		}

		// Random update
		long txId = dbh.startTransaction();
		Random random = new Random(1);
		int updateCnt = recordCnt / 4;// update 1/4th of the records
		int varFldUpdate = 0;
		updateCnt = 206;
		for (int i = 0; i < updateCnt; i++) {
			int ran = random.nextInt();
			if (ran < 0) {
				ran = -ran;
			}
			int ix = ran % recordCnt;

			DBTestUtils.fillRecord(recs[ix], varDataSize);
			int r = varFldUpdate % 4;
			if ((r & 0x01) == 1 && strColumn >= 0) {
				// Update String field with null
				StringField sf = (StringField) recs[ix].getField(strColumn);
				sf.setString(null);
			}
			else if ((r & 0x02) == 2 && binColumn >= 0) {
				// Update binary field with null
				BinaryField bf = (BinaryField) recs[ix].getField(binColumn);
				bf.setBinaryData(null);
			}
			table.putRecord(recs[ix]);
			++varFldUpdate;
		}
		dbh.endTransaction(txId, true);

		assertEquals(recordCnt, table.getRecordCount());

		int[] indexedColumns = table.getIndexedColumns();
		for (int colIx : indexedColumns) {

			Arrays.sort(recs, new RecColumnComparator(colIx));

			// Forward iteration (no start)
			int recIx = 0;
			RecordIterator iter = table.indexIterator(colIx);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Forward iteration (start in middle - specify primary key)
			recIx = recordCnt / 2;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Reverse iteration (end - specify primary key)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Reverse iteration (start in middle - specify primary key)
			recIx = recordCnt / 2;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Forward iteration (start in middle)
			recIx = findStart(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Reverse iteration (end)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Reverse iteration (start in middle)
			recIx = findEnd(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			if (recs[0].getField(colIx) instanceof LongField) {

				// Forward iteration (start in middle - specify primary key)
				recIx = findStart(recs, recordCnt / 2, colIx);
				Field startValue = new LongField();
				startValue.setLongValue(recs[recIx].getField(colIx).getLongValue() - 1);
				iter = table.indexIteratorAfter(colIx, startValue);
				while (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
				assertEquals(recordCnt, recIx);

				// Reverse iteration (start in middle)
				recIx = findEnd(recs, recordCnt / 2, colIx);
				startValue.setLongValue(recs[recIx].getField(colIx).getLongValue() + 1);
				iter = table.indexIteratorBefore(colIx, startValue);
				while (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[recIx--], rec);
				}
				assertEquals(-1, recIx);

			}

		}

	}

	/**
	 * Test record iterator.
	 * 
	 * @param testStoredDB test against a stored database if true, else test against cached database
	 *            only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void iterateRecords(boolean testStoredDB, int schemaType, int recordCnt,
			long keyIncrement, int varDataSize, boolean doUndoRedo) throws IOException {

		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomTableRecords(schemaType, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(schemaType, recordCnt, keyIncrement, varDataSize);
		}

		if (testStoredDB) {
			saveAsAndReopen(dbName);
		}
		Table table = dbh.getTable(table1Name);
		assertEquals(recordCnt, table.getRecordCount());

		if (doUndoRedo) {
			dbh.undo();
			dbh.redo();
			table = dbh.getTable(table1Name);
			assertEquals(recordCnt, table.getRecordCount());
		}

		int[] indexedColumns = table.getIndexedColumns();
		for (int colIx : indexedColumns) {
			Arrays.sort(recs, new RecColumnComparator(colIx));

			int recIx;
			RecordIterator iter;
			ArrayList<Field> indexFields = new ArrayList<>();// list of unique index field values

			// Forward iteration (default iterator with no start) - also collect unique fields
			Field lastIndex = null;
			recIx = 0;
			iter = table.indexIterator(colIx);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx], rec);
				Field indexField = recs[recIx].getField(colIx);
				if (lastIndex == null || !lastIndex.equals(indexField)) {
					indexFields.add(indexField);
					lastIndex = indexField;
				}
				++recIx;
			}
			assertEquals(recordCnt, recIx);

			// Backward iteration (default iterator with no start)
			recIx = 0;
			iter = table.indexIterator(colIx);
			assertTrue(!iter.hasPrevious());

			// Forward iteration (after end)
			iter = table.indexIteratorAfter(colIx, recs[recordCnt - 1].getField(colIx));
			assertTrue(!iter.hasNext());

			// Backward iteration (before first)
			recIx = 0;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			assertTrue(!iter.hasPrevious());

			// Backward iteration (after first)
			int startIx = 0;
			recIx = findEnd(recs, startIx, colIx);
			iter = table.indexIteratorAfter(colIx, recs[startIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);
			assertTrue(!iter.hasPrevious());

			// Forward iteration (before first - specify primary key)
			startIx = 0;
			recIx = findStart(recs, startIx, colIx);
			iter = table.indexIteratorBefore(colIx, recs[startIx].getField(colIx),
				recs[startIx].getKeyField());
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Backward iteration (before first - specify primary key)
			startIx = 0;
			recIx = findStart(recs, startIx, colIx);
			iter = table.indexIteratorBefore(colIx, recs[startIx].getField(colIx),
				recs[startIx].getKeyField());
			assertTrue(!iter.hasPrevious());

			// Forward iteration (before first)
			recIx = 0;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Backward iteration (before first)
			recIx = 0;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			assertTrue(!iter.hasPrevious());

			// Forward iteration (end - specify primary key)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			assertTrue(!iter.hasNext());

			// Backward iteration (end - specify primary key)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Forward iteration (end)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			assertTrue(!iter.hasNext());

			// Backward iteration (end)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Forward iteration (start in middle - specify primary key)
			recIx = recordCnt / 2;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Backward iteration (start in middle - specify primary key)
			recIx = recordCnt / 2;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx),
				recs[recIx].getKeyField());
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Forward iteration (from start in middle)
			recIx = findStart(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Backward iteration (from start in middle)
			recIx = findStart(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[--recIx], rec);
			}
			assertEquals(0, recIx);

			// Forward iteration (from end in middle)
			recIx = findEnd(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[++recIx], rec);
			}
			assertEquals(recordCnt - 1, recIx);

			// Reverse iteration (from end in middle)
			recIx = findEnd(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Forward Range iterator
			int minIx = findStart(recs, recordCnt / 10, colIx);
			int maxIx = findEnd(recs, recordCnt / 5, colIx);
			recIx = minIx;
			iter = table.indexIterator(colIx, recs[minIx].getField(colIx),
				recs[maxIx].getField(colIx), true);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(maxIx + 1, recIx);

			// Full forward record iterator
			recIx = 0;
			iter = table.indexIterator(colIx, null, null, true);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Backward Range iterator
			minIx = findStart(recs, recordCnt / 10, colIx);
			maxIx = findEnd(recs, recordCnt / 5, colIx);
			recIx = maxIx;
			iter = table.indexIterator(colIx, recs[minIx].getField(colIx),
				recs[maxIx].getField(colIx), false);
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(minIx - 1, recIx);

			// Full reverse record iterator
			recIx = recordCnt - 1;
			iter = table.indexIterator(colIx, null, null, false);
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			if (recs[0].getField(colIx) instanceof LongField) {

				// Forward iteration (after end)
				long k = recs[recordCnt - 1].getField(colIx).getLongValue() + 1;
				iter = table.indexIteratorBefore(colIx, new LongField(k));
				assertTrue(!iter.hasNext());

				// Forward iteration (start in middle - specify primary key)
				recIx = findStart(recs, recordCnt / 2, colIx);
				Field startValue = new LongField();
				startValue.setLongValue(recs[recIx].getField(colIx).getLongValue() - 1);
				iter = table.indexIteratorAfter(colIx, startValue);
				while (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
				assertEquals(recordCnt, recIx);

				// Backward iteration (start in middle)
				recIx = findEnd(recs, recordCnt / 2, colIx);
				startValue.setLongValue(recs[recIx].getField(colIx).getLongValue() + 1);
				iter = table.indexIteratorBefore(colIx, startValue);
				while (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[recIx--], rec);
				}
				assertEquals(-1, recIx);
			}

			//*******************************************************************

			// Multi-direction check starting with forward iteration (start in middle)
			recIx = findStart(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			for (int i = 0; i < 2; i++) {
				if (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
			}
			--recIx;
			for (int i = 0; i < 2; i++) {
				if (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[recIx--], rec);
				}
			}
			++recIx;
			for (int i = 0; i < 2; i++) {
				if (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
			}
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			// Multi-direction check starting with backward iteration (start in middle)
			recIx = findStart(recs, recordCnt / 2, colIx);
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			--recIx;
			for (int i = 0; i < 2; i++) {
				if (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[recIx--], rec);
				}
			}
			++recIx;
			for (int i = 0; i < 2; i++) {
				if (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
			}
			--recIx;
			for (int i = 0; i < 2; i++) {
				if (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[recIx--], rec);
				}
			}
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Multi-direction check starting with forward iteration (start at End)
			recIx = recordCnt - 1;
			iter = table.indexIteratorAfter(colIx, recs[recIx].getField(colIx));
			for (int i = 0; i < 3; i++) {
				if (iter.hasNext()) {
					DBRecord rec = iter.next();
					assertEquals(recs[recIx++], rec);
				}
			}
			assertEquals(recordCnt - 1, recIx);
			while (iter.hasPrevious()) {
				DBRecord rec = iter.previous();
				assertEquals(recs[recIx--], rec);
			}
			assertEquals(-1, recIx);

			// Multi-direction check starting with backward iteration (start at Front)
			recIx = 0;
			iter = table.indexIteratorBefore(colIx, recs[recIx].getField(colIx));
			for (int i = 0; i < 3; i++) {
				if (iter.hasPrevious()) {
					DBRecord rec = iter.previous();
					assertEquals(recs[--recIx], rec);
				}
			}
			assertEquals(0, recIx);
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				assertEquals(recs[recIx++], rec);
			}
			assertEquals(recordCnt, recIx);

			//
			// Index Field Iterator does not support variable length fields
			//
			if (lastIndex.isVariableLength()) {
				continue;// skip remain tests
			}

			// Index field iterator (all unique index values)
			minIx = 0;
			maxIx = indexFields.size() - 1;
			DBFieldIterator fiter = table.indexFieldIterator(colIx);
			int ix = minIx;
			while (fiter.hasNext()) {
				Field f = fiter.next();
				assertEquals(indexFields.get(ix++), f);
			}
			assertEquals(maxIx + 1, ix);

			// Index field iterator (forward range of unique index values)
			minIx = indexFields.size() / 10;
			maxIx = minIx * 2;
			fiter = table.indexFieldIterator(indexFields.get(minIx), indexFields.get(maxIx), true,
				colIx);
			ix = minIx;
			while (fiter.hasNext()) {
				Field f = fiter.next();
				assertEquals(indexFields.get(ix++), f);
			}
			assertEquals(maxIx + 1, ix);

			// Index field iterator (forward over all indexed fields)
			minIx = 0;
			maxIx = indexFields.size() - 1;
			fiter = table.indexFieldIterator(null, null, true, colIx);
			ix = minIx;
			assertTrue("Failed to position before min field", fiter.hasNext());
			while (fiter.hasNext()) {
				Field f = fiter.next();
				assertEquals(indexFields.get(ix++), f);
			}
			assertEquals(maxIx + 1, ix);

			// Index field iterator (reverse range of unique index values)
			fiter = table.indexFieldIterator(indexFields.get(minIx), indexFields.get(maxIx), false,
				colIx);
			ix = maxIx;
			while (fiter.hasPrevious()) {
				Field f = fiter.previous();
				assertEquals(indexFields.get(ix--), f);
			}
			assertEquals(minIx - 1, ix);

			// Index field iterator (reverse over all indexed fields)
			minIx = 0;
			maxIx = indexFields.size() - 1;
			fiter = table.indexFieldIterator(null, null, false, colIx);
			ix = maxIx;
			assertTrue("Failed to position after max field", fiter.hasPrevious());
			while (fiter.hasPrevious()) {
				Field f = fiter.previous();
				assertEquals(indexFields.get(ix--), f);
			}
			assertEquals(-1, ix);

			// Index field iterator (forward range of unique index values)
			startIx = (minIx + maxIx) / 2;
			fiter = table.indexFieldIterator(indexFields.get(minIx), indexFields.get(maxIx),
				indexFields.get(startIx), true, colIx);
			ix = startIx;
			while (fiter.hasNext()) {
				Field f = fiter.next();
				assertEquals(indexFields.get(ix++), f);
			}
			assertEquals(maxIx + 1, ix);

			// Index field iterator (reverse range of unique index values)
			fiter = table.indexFieldIterator(indexFields.get(minIx), indexFields.get(maxIx),
				indexFields.get(startIx), false, colIx);
			ix = startIx;
			while (fiter.hasPrevious()) {
				Field f = fiter.previous();
				assertEquals(indexFields.get(ix--), f);
			}
			assertEquals(minIx - 1, ix);
		}

	}

	/**
	 * Test record iterator.
	 * 
	 * @param testStoredDB test against a stored database if true, else test against cached database
	 *            only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void deleteIteratedRecords(int recordCnt, int testColIx, long keyIncrement,
			int varDataSize) throws IOException {

		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomTableRecords(DBTestUtils.ALL_TYPES, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(DBTestUtils.ALL_TYPES, recordCnt, keyIncrement,
				varDataSize);
		}

		Table table = dbh.getTable(table1Name);

		Arrays.sort(recs, new RecColumnComparator(testColIx));

		// Forward - delete all records
		long txId = dbh.startTransaction();
		RecordIterator iter = table.indexIterator(testColIx);
		int recIx = 0;
		while (iter.hasNext()) {
			assertEquals(recs[recIx++], iter.next());
			assertTrue(iter.delete());
		}
		assertEquals(recIx, recs.length);

		dbh.deleteTable(table1Name);

		dbh.endTransaction(txId, true);

		if (keyIncrement == 0) {
			recs = createRandomTableRecords(DBTestUtils.ALL_TYPES, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(DBTestUtils.ALL_TYPES, recordCnt, keyIncrement,
				varDataSize);
		}

		table = dbh.getTable(table1Name);

		Arrays.sort(recs, new RecColumnComparator(testColIx));

		// Reverse - delete all records
		txId = dbh.startTransaction();
		recIx = recs.length - 1;
		iter = table.indexIterator(testColIx, recs[0].getField(testColIx),
			recs[recIx].getField(testColIx), false);
		while (iter.hasPrevious()) {
			assertEquals(recs[recIx--], iter.previous());
			assertTrue(iter.delete());
		}
		assertEquals(recIx, -1);

		dbh.deleteTable(table1Name);

		dbh.endTransaction(txId, true);
	}

	/**
	 * Test record iterator.
	 * 
	 * @param testStoredDB test against a stored database if true, else test against cached database
	 *            only.
	 * @param recordCnt number of records to test
	 * @param keyIncrement key increment, 0 = random
	 * @param varDataSize size of variable length data fields.
	 * @throws IOException
	 */
	private void deleteIteratedIndexFields(int recordCnt, int testColIx, long keyIncrement,
			int varDataSize) throws IOException {

		DBRecord[] recs = null;
		if (keyIncrement == 0) {
			recs = createRandomTableRecords(DBTestUtils.ALL_TYPES, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(DBTestUtils.ALL_TYPES, recordCnt, keyIncrement,
				varDataSize);
		}
		long txId = dbh.startTransaction();
		try {
			Table table = dbh.getTable(table1Name);

			Arrays.sort(recs, new RecColumnComparator(testColIx));

			// Count unique index values
			int fieldCnt = 0;
			Field lastField = null;
			ArrayList<Field> fieldList = new ArrayList<>();
			for (DBRecord rec : recs) {
				Field f = rec.getField(testColIx);
				if (lastField == null || !lastField.equals(f)) {
					lastField = f;
					fieldList.add(f);
					++fieldCnt;
				}
			}

			//
			// Index Field Iterator does not support variable length fields
			//
			if (lastField.isVariableLength()) {
				return;// skip test
			}

			// Forward - delete all records
			DBFieldIterator iter = table.indexFieldIterator(testColIx);
			int cnt = 0;
			while (iter.hasNext()) {
				assertEquals(fieldList.get(cnt++), iter.next());
				assertTrue(iter.delete());
			}
			assertEquals(fieldCnt, cnt);
			assertEquals(0, table.getRecordCount());
		}
		finally {
			dbh.deleteTable(table1Name);
			dbh.endTransaction(txId, true);
		}

		if (keyIncrement == 0) {
			recs = createRandomTableRecords(DBTestUtils.ALL_TYPES, recordCnt, varDataSize);
		}
		else {
			recs = createOrderedTableRecords(DBTestUtils.ALL_TYPES, recordCnt, keyIncrement,
				varDataSize);
		}
		txId = dbh.startTransaction();

		try {
			Table table = dbh.getTable(table1Name);

			Arrays.sort(recs, new RecColumnComparator(testColIx));

			// Count unique index values
			int fieldCnt = 0;
			Field lastField = null;
			ArrayList<Field> fieldList = new ArrayList<>();
			for (DBRecord rec : recs) {
				Field f = rec.getField(testColIx);
				if (lastField == null || !lastField.equals(f)) {
					lastField = f;
					fieldList.add(f);
					++fieldCnt;
				}
			}

			// Reverse - delete all records

			int cnt = fieldCnt - 1;
			int lastIx = recs.length - 1;
			DBFieldIterator iter = table.indexFieldIterator(recs[0].getField(testColIx),
				recs[lastIx].getField(testColIx), false, testColIx);
			while (iter.hasPrevious()) {
				assertEquals(fieldList.get(cnt--), iter.previous());
				assertTrue(iter.delete());
			}
			assertEquals(-1, cnt);
			assertEquals(0, table.getRecordCount());
		}
		finally {
			dbh.deleteTable(table1Name);
			dbh.endTransaction(txId, true);
		}
	}

	private int findStart(DBRecord[] recs, int startIx, int colIx) {
		Field f = recs[startIx].getField(colIx);
		--startIx;
		while (startIx >= 0 && f.equals(recs[startIx].getField(colIx))) {
			if (startIx == 0) {
				return startIx;
			}
			--startIx;
		}
		return ++startIx;
	}

	private int findEnd(DBRecord[] recs, int startIx, int colIx) {
		Field f = recs[startIx].getField(colIx);
		++startIx;
		while (startIx < recs.length && f.equals(recs[startIx].getField(colIx))) {
			if (startIx == recs.length) {
				return startIx;
			}
			++startIx;
		}
		return --startIx;
	}

	private class RecColumnComparator implements Comparator<DBRecord> {

		int columnIx;

		RecColumnComparator(int columnIx) {
			this.columnIx = columnIx;
		}

		@Override
		public int compare(DBRecord rec1, DBRecord rec2) {
			int r = rec1.getField(columnIx).compareTo(rec2.getField(columnIx));
			if (r == 0) {
				return rec1.getKeyField().compareTo(rec2.getKeyField());
			}
			return r;
		}
	}

	@Test
	public void testRandomRecordIterator() throws IOException {
		iterateRecords(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 0, -1, false);
	}

	@Test
	public void testForwardRecordIterator() throws IOException {
		iterateRecords(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 1, 1, false);
	}

	@Test
	public void testBackwardRecordIterator() throws IOException {
		iterateRecords(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, -1, 1, false);
	}

	@Test
	public void testStoredRandomRecordIterator() throws IOException {
		iterateRecords(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 0, 1, false);
	}

	@Test
	public void testStoredForwardRecordIterator() throws IOException {
		iterateRecords(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 1, 1, false);
	}

	@Test
	public void testStoredBackwardRecordIterator() throws IOException {
		iterateRecords(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, -1, 1, false);
	}

	@Test
	public void testRandomUpdateRecordIterator() throws IOException {
		updateRecordsIterator(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testForwardUpdateRecordIterator() throws IOException {
		updateRecordsIterator(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testBackwardUpdateRecordIterator() throws IOException {
		updateRecordsIterator(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, -1, 1);
	}

	@Test
	public void testStoredUpdateRandomRecordIterator() throws IOException {
		updateRecordsIterator(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 0, 1);
	}

	@Test
	public void testStoredUpdateForwardRecordIterator() throws IOException {
		updateRecordsIterator(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 1, 1);
	}

	@Test
	public void testStoredUpdateBackwardRecordIterator() throws IOException {
		updateRecordsIterator(true, DBTestUtils.ALL_TYPES, ITER_REC_CNT, -1, 1);
	}

	@Test
	public void testRandomRecordIteratorUndoRedo() throws IOException {
		iterateRecords(false, DBTestUtils.ALL_TYPES, ITER_REC_CNT, 0, -1, true);
	}

	@Test
	public void testRecordIteratorExtents() throws IOException {

		DBRecord[] recs = null;
		recs = createOrderedTableRecords(DBTestUtils.SINGLE_SHORT, 30, 2, 1);
		Table table = dbh.getTable(table1Name);
		assertEquals(recs.length, table.getRecordCount());

		// Backward Range iterator
		int colIx = 0;
		Arrays.sort(recs, new RecColumnComparator(colIx));
		int recIx = recs.length - 1;
		Field minField = new ShortField(Short.MIN_VALUE);
		Field maxField = new ShortField(Short.MAX_VALUE);
		RecordIterator iter = table.indexIterator(colIx, minField, maxField, false);
		while (iter.hasPrevious()) {
			DBRecord rec = iter.previous();
			assertEquals(recs[recIx--], rec);
		}
		assertEquals(recIx, -1);
	}

	@Test
	public void testRecordIteratorDelete() throws IOException {
		for (int colIx : DBTestUtils.getIndexedColumns(DBTestUtils.ALL_TYPES)) {
			deleteIteratedRecords(ITER_REC_CNT, colIx, 1, 1);
		}
		for (int colIx : DBTestUtils.getIndexedColumns(DBTestUtils.ALL_TYPES)) {
			deleteIteratedRecords(ITER_REC_CNT, colIx, 0, 1);
		}
	}

	@Test
	public void testIndexFieldIteratorDelete() throws IOException {
		for (int colIx : DBTestUtils.getIndexedColumns(DBTestUtils.ALL_TYPES)) {
			deleteIteratedIndexFields(ITER_REC_CNT, colIx, 1, 1);
		}
		for (int colIx : DBTestUtils.getIndexedColumns(DBTestUtils.ALL_TYPES)) {
			deleteIteratedIndexFields(ITER_REC_CNT, colIx, 0, 1);
		}
	}

}
