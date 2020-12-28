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

import org.junit.*;

import generic.test.AbstractGenericTest;

public class TableConcurrencyTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private DBHandle dbh;
	private long txId;
	private Table table1;
	private Table table2;
	private Schema schema1;
	private Schema schema2;

	/**
	 * Constructor for DBTest1.
	 * @param arg0
	 */
	public TableConcurrencyTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
		txId = dbh.startTransaction();
		table1 =
			DBTestUtils.createLongKeyTable(dbh, "TABLE1", DBTestUtils.SINGLE_LONG, false, false);
		table2 = DBTestUtils.createBinaryKeyTable(dbh, "TABLE2", DBTestUtils.SINGLE_LONG, false);
		schema1 = table1.getSchema();
		schema2 = table2.getSchema();
		for (byte i = 0; i < 100; i++) {

			DBRecord rec = schema1.createRecord(i);
			rec.setLongValue(0, i);
			table1.putRecord(rec);

			rec = schema2.createRecord(getField(i));
			rec.setLongValue(0, i);
			table2.putRecord(rec);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (dbh != null) {
			dbh.endTransaction(txId, true);
			dbh.close();
		}

	}

	private BinaryField getField(byte i) {
		return new BinaryField(new byte[] { i });
	}

	// Test using Table.longKeyIterator()
	@Test
	public void testLongKeyIteratorA() {
		try {
			DBLongIterator iter = table1.longKeyIterator();

			table1.deleteRecord(0);// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(1, iter.next());

			assertTrue(iter.hasNext());
			table1.deleteRecord(2);// iterator already primed
			assertEquals(2, iter.next());

			assertTrue(iter.hasNext());
			assertEquals(3, iter.next());

			table1.deleteRecord(4);// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(5, iter.next());

			iter.delete();

			assertTrue(iter.hasNext());
			assertEquals(6, iter.next());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.longKeyIterator(long)
	@Test
	public void testLongKeyIteratorB() {
		try {
			DBLongIterator iter = table1.longKeyIterator(10);

			table1.deleteRecord(10);// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(11, iter.next());

			assertTrue(iter.hasNext());
			table1.deleteRecord(12);// iterator already primed
			assertEquals(12, iter.next());

			assertTrue(iter.hasNext());
			assertEquals(13, iter.next());

			table1.deleteRecord(14);// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(15, iter.next());

			iter.delete();

			assertTrue(iter.hasNext());
			assertEquals(16, iter.next());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.longKeyIterator(long) reverse
	@Test
	public void testLongKeyIteratorBReverse() {
		try {
			DBLongIterator iter = table1.longKeyIterator(10);

			table1.deleteRecord(10);// iterator not yet used

			assertTrue(iter.hasPrevious());
			assertEquals(9, iter.previous());

			assertTrue(iter.hasPrevious());
			table1.deleteRecord(8);// iterator already primed
			assertEquals(8, iter.previous());

			assertTrue(iter.hasPrevious());
			assertEquals(7, iter.previous());

			table1.deleteRecord(6);// iterator not yet primed

			assertTrue(iter.hasPrevious());
			assertEquals(5, iter.previous());

			iter.delete();

			assertTrue(iter.hasPrevious());
			assertEquals(4, iter.previous());

			assertTrue(iter.hasPrevious());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.longKeyIterator(long,long,long)
	@Test
	public void testLongKeyIteratorC() {
		try {
			DBLongIterator iter = table1.longKeyIterator(10, 15, 10);

			table1.deleteRecord(10);// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(11, iter.next());

			assertTrue(iter.hasNext());
			table1.deleteRecord(12);// iterator already primed
			assertEquals(12, iter.next());

			assertTrue(iter.hasNext());
			assertEquals(13, iter.next());

			table1.deleteRecord(14);// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(15, iter.next());

			iter.delete();

			assertTrue(!iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.iterator(long)
	@Test
	public void testLongKeyRecordIterator() {
		try {
			RecordIterator iter = table1.iterator(10);

			table1.deleteRecord(10);// iterator already primed

			assertTrue(iter.hasNext());
			DBRecord rec = iter.next();
			assertEquals(10, rec.getKey());

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(11, rec.getKey());

			assertTrue(iter.hasNext());
			table1.deleteRecord(12);// iterator already primed
			rec = iter.next();
			assertEquals(12, rec.getKey());

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(13, rec.getKey());

			table1.deleteRecord(14);// iterator not yet primed

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(15, rec.getKey());

			iter.delete();

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(16, rec.getKey());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.iterator(long,long,long)
	@Test
	public void testLongKeyRecordIteratorReverse() {
		try {
			RecordIterator iter = table1.iterator(2, 20, 10);

			table1.deleteRecord(10);// iterator already primed

			assertTrue(iter.hasPrevious());
			DBRecord rec = iter.previous();
			assertEquals(10, rec.getKey());

			assertTrue(iter.hasPrevious());
			rec = iter.previous();
			assertEquals(9, rec.getKey());

			assertTrue(iter.hasPrevious());
			table1.deleteRecord(8);// iterator already primed
			rec = iter.previous();
			assertEquals(8, rec.getKey());

			assertTrue(iter.hasPrevious());
			rec = iter.previous();
			assertEquals(7, rec.getKey());

			table1.deleteRecord(6);// iterator not yet primed

			assertTrue(iter.hasPrevious());
			rec = iter.previous();
			assertEquals(5, rec.getKey());

			iter.delete();

			assertTrue(iter.hasPrevious());
			rec = iter.previous();
			assertEquals(4, rec.getKey());

			assertTrue(iter.hasPrevious());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.fieldKeyIterator()
	@Test
	public void testVarKeyIteratorA() {
		try {
			DBFieldIterator iter = table2.fieldKeyIterator();

			table2.deleteRecord(getField((byte) 0));// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 1), iter.next());

			assertTrue(iter.hasNext());
			table2.deleteRecord(getField((byte) 2));// iterator already primed
			assertEquals(getField((byte) 2), iter.next());

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 3), iter.next());

			table2.deleteRecord(getField((byte) 4));// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 5), iter.next());

			iter.delete();

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 6), iter.next());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.fieldKeyIterator(Field)
	@Test
	public void testVarKeyIteratorB() {
		try {
			DBFieldIterator iter = table2.fieldKeyIterator(getField((byte) 10));

			table2.deleteRecord(getField((byte) 10));// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 11), iter.next());

			assertTrue(iter.hasNext());
			table2.deleteRecord(getField((byte) 12));// iterator already primed
			assertEquals(getField((byte) 12), iter.next());

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 13), iter.next());

			table2.deleteRecord(getField((byte) 14));// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 15), iter.next());

			iter.delete();

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 16), iter.next());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.fieldKeyIterator(Field) reverse
	@Test
	public void testVarKeyIteratorBReverse() {
		try {
			DBFieldIterator iter = table2.fieldKeyIterator(getField((byte) 10));

			table2.deleteRecord(getField((byte) 10));// iterator not yet used

			assertTrue(iter.hasPrevious());
			assertEquals(getField((byte) 9), iter.previous());

			assertTrue(iter.hasPrevious());
			table2.deleteRecord(getField((byte) 12));// iterator already primed
			assertEquals(getField((byte) 8), iter.previous());

			assertTrue(iter.hasPrevious());
			assertEquals(getField((byte) 7), iter.previous());

			table2.deleteRecord(getField((byte) 6));// iterator not yet primed

			assertTrue(iter.hasPrevious());
			assertEquals(getField((byte) 5), iter.previous());

			iter.delete();

			assertTrue(iter.hasPrevious());
			assertEquals(getField((byte) 4), iter.previous());

			assertTrue(iter.hasPrevious());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.fieldKeyIterator(Field,Field,Field)
	@Test
	public void testVarKeyIteratorC() {
		try {
			DBFieldIterator iter = table2.fieldKeyIterator(getField((byte) 10), getField((byte) 15),
				getField((byte) 10));

			table2.deleteRecord(getField((byte) 10));// iterator not yet used

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 11), iter.next());

			assertTrue(iter.hasNext());
			table2.deleteRecord(getField((byte) 12));// iterator already primed
			assertEquals(getField((byte) 12), iter.next());

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 13), iter.next());

			table2.deleteRecord(getField((byte) 14));// iterator not yet primed

			assertTrue(iter.hasNext());
			assertEquals(getField((byte) 15), iter.next());

			iter.delete();

			assertTrue(!iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

	// Test using Table.iterator(Field)
	@Test
	public void testVarKeyRecordIterator() {
		try {
			RecordIterator iter = table2.iterator(getField((byte) 10));

			table2.deleteRecord(getField((byte) 10));// iterator already primed

			assertTrue(iter.hasNext());
			DBRecord rec = iter.next();
			assertEquals(getField((byte) 10), rec.getKeyField());

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(getField((byte) 11), rec.getKeyField());

			assertTrue(iter.hasNext());
			table2.deleteRecord(getField((byte) 12));// iterator already primed
			rec = iter.next();
			assertEquals(getField((byte) 12), rec.getKeyField());

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(getField((byte) 13), rec.getKeyField());

			table2.deleteRecord(getField((byte) 14));// iterator not yet primed

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(getField((byte) 15), rec.getKeyField());

			iter.delete();

			assertTrue(iter.hasNext());
			rec = iter.next();
			assertEquals(getField((byte) 16), rec.getKeyField());

			assertTrue(iter.hasNext());

		}
		catch (Exception e) {
			Assert.fail(e.toString());
		}
	}

}
