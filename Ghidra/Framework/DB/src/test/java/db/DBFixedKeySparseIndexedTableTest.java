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

	@Test
	public void testFixedKeyIterator() throws IOException {

		long txId = dbh.startTransaction();
		Table table =
			DBTestUtils.createFixedKeyTable(dbh, table1Name, DBTestUtils.ALL_TYPES, true, true);
		Schema schema = table.getSchema();
		for (int i = 0; i < schema.getFieldCount(); i++) {
			assertTrue(schema.isSparseColumn(i));
		}

		int cnt = schema.getFieldCount();
		for (int i = 0; i < cnt; i++) {
			Field key = new FixedField10(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, (byte) i });
			DBRecord r = schema.createRecord(key);

			Field f = schema.getField(i);
			if (f.isVariableLength()) {
				f.setBinaryData(new byte[] { 'X' });
			}
			else {
				f = f.getMaxValue();
			}
			r.setField(i, f);

			int nextCol = i + 1;
			if (nextCol < cnt) {
				f = schema.getField(nextCol);
				if (f.isVariableLength()) {
					f.setBinaryData(new byte[] { 'x' });
				}
				else {
					f = f.getMinValue();
				}
				r.setField(nextCol, f);
			}

			table.putRecord(r);
		}

		dbh.endTransaction(txId, true);

		saveAsAndReopen(dbName);

		table = dbh.getTable(table1Name);
		assertEquals(cnt, table.getRecordCount());

		// see DBTestUtils for schema column types

		// Index does not track null/zero values
		assertEquals(0, table.findRecords(IntField.ZERO_VALUE, 2).length);
		assertEquals(0, table.findRecords(ShortField.ZERO_VALUE, 3).length);
		assertEquals(0, table.findRecords(LongField.ZERO_VALUE, 4).length);
		assertEquals(0, table.findRecords(StringField.NULL_VALUE, 5).length);
		assertEquals(0, table.findRecords(new BinaryField(), 6).length);
		assertEquals(0, table.findRecords(FixedField10.ZERO_VALUE, 7).length);

		assertEquals(1, table.findRecords(IntField.MAX_VALUE, 2).length);
		assertEquals(1, table.findRecords(ShortField.MAX_VALUE, 3).length);
		assertEquals(1, table.findRecords(LongField.MAX_VALUE, 4).length);
		assertEquals(1, table.findRecords(new StringField("X"), 5).length);
		assertEquals(1, table.findRecords(new BinaryField(new byte[] { 'X' }), 6).length);
		assertEquals(1, table.findRecords(FixedField10.MAX_VALUE, 7).length);

		assertEquals(1, table.findRecords(IntField.MIN_VALUE, 2).length);
		assertEquals(1, table.findRecords(ShortField.MIN_VALUE, 3).length);
		assertEquals(1, table.findRecords(LongField.MIN_VALUE, 4).length);
		assertEquals(1, table.findRecords(new StringField("x"), 5).length);
		assertEquals(1, table.findRecords(new BinaryField(new byte[] { 'x' }), 6).length);
		assertEquals(0, table.findRecords(FixedField10.MIN_VALUE, 7).length); // same as zero/null
	}

}
