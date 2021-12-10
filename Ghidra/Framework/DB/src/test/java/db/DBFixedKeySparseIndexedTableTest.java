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

import org.junit.*;

import db.buffers.*;
import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import utilities.util.FileUtilities;

public class DBFixedKeySparseIndexedTableTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 2048;// keep small for chained buffer testing
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final String table1Name = "TABLE1";

	private static final int BOOLEAN_COL = 0; // not indexed
	private static final int BYTE_COL = 1; // not indexed
	private static final int INT_COL = 2;
	private static final int SHORT_COL = 3;
	private static final int LONG_COL = 4;
	private static final int STR_COL = 5;
	private static final int BIN_COL = 6;
	private static final int FIXED10_COL = 7;

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

	@Test
	public void testEmptyFixedKeyIterator() throws IOException {

		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, true, true);
		Schema schema = table.getSchema();
		for (int i = 0; i < schema.getFieldCount(); i++) {
			assertTrue(schema.isSparseColumn(i));
		}
		dbh.endTransaction(txId, true);

		dbh.undo();
		dbh.redo();

		saveAsAndReopen(dbName);

		table = dbh.getTable(table1Name);
		assertEquals(0, table.getRecordCount());

		assertEquals(schema, table.getSchema());

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

	private void populateFixedKeySparseRecords() throws IOException {
		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, true, true);
		Schema schema = table.getSchema();
		for (int i = 0; i < schema.getFieldCount(); i++) {
			assertTrue(schema.isSparseColumn(i));
		}

//		DBRecord r1 = schema.createRecord(FixedField10.ZERO_VALUE);
//		System.out.println("Sparse record test columns:");
//		for (Field f : r1.getFields()) {
//			System.out.println("   " + f.toString());
//		}

		int cnt = schema.getFieldCount();

//		System.out.println("Write sparse records:");
		for (int i = 0; i < cnt + 1; i++) {
			Field key = new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) i });
			DBRecord r = schema.createRecord(key);

			for (Field f : r.getFields()) {
				// all fields correspond to a sparse columns and 
				// should have a null state initially
				assertTrue(f.isNull());
				assertTrue(f.copyField().isNull());
			}

			if (i < cnt) {
				Field f = schema.getField(i);
				if (f.isVariableLength()) {
					f.setBinaryData(new byte[] { 'X' });
				}
				else {
					f = f.getMaxValue();
				}
				r.setField(i, f);
			}

			// set min value all fields before i
			for (int m = 0; m < i; m++) {
				Field f = schema.getField(m);
				if (f.isVariableLength()) {
					f.setBinaryData(new byte[] { 'x' });
				}
				else {
					f = f.getMinValue();
				}
				r.setField(m, f);
			}

//			// NOTE: sparse columns default to a null state if not explicitly set

//			System.out.println("-> " + r.getField(2) + ", " + r.getField(6).toString() + ", " +
//				r.getField(7).toString());

			table.putRecord(r);
		}

		assertEquals(cnt + 1, table.getRecordCount());

		dbh.endTransaction(txId, true);

		saveAsAndReopen(dbName);
	}

	@Test
	public void testFixedKeyIterator() throws IOException {

		populateFixedKeySparseRecords();

		Table table = dbh.getTable(table1Name);
		int cnt = table.getSchema().getFieldCount();
		assertEquals(8, cnt); // testing 8 field types as sparse columns in 9 data records
		assertEquals(cnt + 1, table.getRecordCount());

		// see DBTestUtils for schema column types

//		System.out.println("Read sparse records:");
		int recordIndex = 0;
		RecordIterator iterator = table.iterator();
		while (iterator.hasNext()) {
			DBRecord r = iterator.next();

			Field key =
				new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) recordIndex });
			assertEquals(key, r.getKeyField());

//			System.out.println("<- " + r.getField(2) + ", " + r.getField(6).toString() + ", " +
//				r.getField(7).toString());

			// recordIndex used as walking columnIndex
			int columnIndex = recordIndex;

			if (columnIndex < cnt) {
				Field f = r.getField(columnIndex);
				if (f.isVariableLength()) {
					Field f2 = f.newField();
					f2.setBinaryData(new byte[] { 'X' });
					assertEquals(f2, f);
				}
				else {
					assertEquals(f.getMaxValue(), f);
				}
			}

			// set min value all fields before i
			for (int m = 0; m < columnIndex; m++) {
				Field f = r.getField(m);
				if (f.isVariableLength()) {
					Field f2 = f.newField();
					f2.setBinaryData(new byte[] { 'x' });
					assertEquals(f2, f);
				}
				else {
					assertEquals(f.getMinValue(), f);
				}
			}

			for (int n = columnIndex + 1; n < cnt; n++) {
				Field f = r.getField(n);
				assertTrue(f.isNull());
				assertTrue(f.copyField().isNull());
			}

			++recordIndex;
		}

	}

	@Test
	public void testFixedKeySparseIndex() throws IOException {

		populateFixedKeySparseRecords();

		Table table = dbh.getTable(table1Name);
		int cnt = table.getSchema().getFieldCount();
		assertEquals(8, cnt); // testing 8 field types as sparse columns in 9 data records
		assertEquals(cnt + 1, table.getRecordCount());

		// see DBTestUtils for schema column types

		// null state/value not indexed (corresponds to a 0 primitive value)
		assertEquals(0, table.findRecords(IntField.ZERO_VALUE, INT_COL).length);
		assertEquals(0, table.findRecords(ShortField.ZERO_VALUE, SHORT_COL).length);
		assertEquals(0, table.findRecords(LongField.ZERO_VALUE, LONG_COL).length);
		assertEquals(0, table.findRecords(StringField.NULL_VALUE, STR_COL).length);
		assertEquals(0, table.findRecords(new BinaryField(), BIN_COL).length);
		assertEquals(1, table.findRecords(FixedField10.ZERO_VALUE, FIXED10_COL).length); // last record has a FixedField10.ZERO_VALUE

		assertEquals(1, table.findRecords(IntField.MAX_VALUE, INT_COL).length);
		assertEquals(1, table.findRecords(ShortField.MAX_VALUE, SHORT_COL).length);
		assertEquals(1, table.findRecords(LongField.MAX_VALUE, LONG_COL).length);
		assertEquals(1, table.findRecords(new StringField("X"), STR_COL).length);
		assertEquals(1, table.findRecords(new BinaryField(new byte[] { 'X' }), BIN_COL).length);
		assertEquals(1, table.findRecords(FixedField10.MAX_VALUE, FIXED10_COL).length);

		assertEquals(6, table.findRecords(IntField.MIN_VALUE, INT_COL).length);
		assertEquals(5, table.findRecords(ShortField.MIN_VALUE, SHORT_COL).length);
		assertEquals(4, table.findRecords(LongField.MIN_VALUE, LONG_COL).length);
		assertEquals(3, table.findRecords(new StringField("x"), STR_COL).length);
		assertEquals(2, table.findRecords(new BinaryField(new byte[] { 'x' }), BIN_COL).length);
		assertEquals(1, table.findRecords(FixedField10.MIN_VALUE, FIXED10_COL).length); // same as ZERO_VALUE

		assertEquals(6, table.getMatchingRecordCount(IntField.MIN_VALUE, INT_COL));
		assertEquals(5, table.getMatchingRecordCount(ShortField.MIN_VALUE, SHORT_COL));
		assertEquals(4, table.getMatchingRecordCount(LongField.MIN_VALUE, LONG_COL));
		assertEquals(3, table.getMatchingRecordCount(new StringField("x"), STR_COL));
		assertEquals(2, table.getMatchingRecordCount(new BinaryField(new byte[] { 'x' }), BIN_COL));
		assertEquals(1, table.getMatchingRecordCount(FixedField10.MIN_VALUE, FIXED10_COL)); // same as ZERO_VALUE
	}

	private int count(DBFieldIterator iter) throws IOException {
		int count = 0;
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		return count;
	}

	private int count(RecordIterator iter) throws IOException {
		int count = 0;
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		return count;
	}

	@Test
	public void testFixedKeySparseIndexIterator() throws IOException {

		populateFixedKeySparseRecords();

		Table table = dbh.getTable(table1Name);
		int cnt = table.getSchema().getFieldCount();
		assertEquals(8, cnt); // testing 8 field types as sparse columns in 9 data records
		assertEquals(cnt + 1, table.getRecordCount());

		// see DBTestUtils for schema column types

		// null state/value not indexed

		assertEquals(7, count(table.indexIterator(INT_COL)));
		assertEquals(6, count(table.indexIterator(SHORT_COL)));
		assertEquals(5, count(table.indexIterator(LONG_COL)));
		assertEquals(4, count(table.indexIterator(STR_COL)));
		assertEquals(3, count(table.indexIterator(BIN_COL)));
		assertEquals(2, count(table.indexIterator(FIXED10_COL)));
	}

	@Test
	public void testFixedKeySparseIndexFieldIterator() throws IOException {

		populateFixedKeySparseRecords();

		Table table = dbh.getTable(table1Name);
		int cnt = table.getSchema().getFieldCount();
		assertEquals(8, cnt); // testing 8 field types as sparse columns in 9 data records
		assertEquals(cnt + 1, table.getRecordCount());

		// see DBTestUtils for schema column types

		// null state/value not indexed - only 2 unique values were used
		
		assertEquals(2, count(table.indexFieldIterator(INT_COL)));
		assertEquals(2, count(table.indexFieldIterator(SHORT_COL)));
		assertEquals(2, count(table.indexFieldIterator(LONG_COL)));
		try {
			assertEquals(2, count(table.indexFieldIterator(STR_COL)));
		}
		catch (UnsupportedOperationException e) {
			// expected
		}
		try {
			assertEquals(2, count(table.indexFieldIterator(BIN_COL)));
		}
		catch (UnsupportedOperationException e) {
			// expected
		}
		assertEquals(2, count(table.indexFieldIterator(FIXED10_COL)));
	}

}

