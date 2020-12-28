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

import org.junit.*;

import generic.test.AbstractGenericTest;

public class DBLongKeyChainedBufferUseTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;// keep small for chained buffer testing
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private DBHandle dbh;
	private int bigLength; // field length which will trigger use of indirect Chained Buffer storage

	/**
	 * Constructor
	 */
	public DBLongKeyChainedBufferUseTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
		bigLength = ((dbh.getBufferSize() - LongKeyRecordNode.RECORD_LEAF_HEADER_SIZE) >> 2) - 13; // see VarRecNode
	}

	@After
	public void tearDown() throws Exception {
		if (dbh != null) {
			dbh.close();
		}
	}

	private String getBigString(String prefix, int k) {
		return getBigString(prefix, k, 1);
	}

	private String getBigString(String prefix, int k, int factor) {
		String str = prefix + k;
		StringBuilder buf = new StringBuilder();
		int iter = ((bigLength * factor) / str.length()) + 1;
		for (int i = 0; i < iter; i++) {
			buf.append(str);
		}
		return buf.toString();
	}

	private String getSmallString(String prefix, int k) {
		return "small_" + prefix + k;
	}

	private Table fillTableBigRecs(int count) throws Exception {
		long txId = dbh.startTransaction();

		Schema schema = new Schema(0, "Enum ID",
			new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
				ByteField.INSTANCE, ShortField.INSTANCE, IntField.INSTANCE },
			new String[] { "str1", "str2", "long", "byte", "short", "int" });

		Table table = dbh.createTable("TABLE1", schema);

		// Add even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = schema.createRecord(k);
			rec.setString(0, getBigString("a", k));
			rec.setString(1, getSmallString("b", k));
			rec.setLongValue(2, 0x2222222222222222L);
			rec.setByteValue(3, (byte) 0x33);
			rec.setShortValue(4, (short) 0x4444);
			rec.setIntValue(5, 0x55555555);
			table.putRecord(rec);
		}

		// Add odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = schema.createRecord(k);
			rec.setString(0, getBigString("a", k));
			rec.setString(1, getSmallString("b", k));
			rec.setLongValue(2, 0x2222222222222222L);
			rec.setByteValue(3, (byte) 0x33);
			rec.setShortValue(4, (short) 0x4444);
			rec.setIntValue(5, 0x55555555);
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		return table;
	}

	private Table fillTableSmallRecs(int count) throws Exception {
		long txId = dbh.startTransaction();

		Schema schema = new Schema(0, "Enum ID",
			new Field[] { StringField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
				ByteField.INSTANCE, ShortField.INSTANCE, IntField.INSTANCE },
			new String[] { "str1", "str2", "long", "byte", "short", "int" });

		Table table = dbh.createTable("TABLE1", schema);

		// Add even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = schema.createRecord(k);
			rec.setString(0, getSmallString("a", k));
			rec.setString(1, getSmallString("b", k));
			rec.setLongValue(2, 0x2222222222222222L);
			rec.setByteValue(3, (byte) 0x33);
			rec.setShortValue(4, (short) 0x4444);
			rec.setIntValue(5, 0x55555555);
			table.putRecord(rec);
		}

		// Add odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = schema.createRecord(k);
			rec.setString(0, getSmallString("a", k));
			rec.setString(1, getSmallString("b", k));
			rec.setLongValue(2, 0x2222222222222222L);
			rec.setByteValue(3, (byte) 0x33);
			rec.setShortValue(4, (short) 0x4444);
			rec.setIntValue(5, 0x55555555);
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		return table;
	}

	private void assertPrimitiveColumns(DBRecord rec) {
		Assert.assertEquals(0x2222222222222222L, rec.getLongValue(2));
		Assert.assertEquals((byte) 0x33, rec.getByteValue(3));
		Assert.assertEquals((short) 0x4444, rec.getShortValue(4));
		Assert.assertEquals(0x55555555, rec.getIntValue(5));
	}

	@Test
	public void testNodeFillBig() throws Exception {

		Table table = fillTableBigRecs(256);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(getBigString("a", k), rec.getString(0));
			Assert.assertEquals(getSmallString("b", k), rec.getString(1));
			assertPrimitiveColumns(rec);
		}

	}

	@Test
	public void testNodeFillSmall() throws Exception {

		Table table = fillTableSmallRecs(256);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(rec.getString(0), getSmallString("a", k));
			Assert.assertEquals(rec.getString(1), getSmallString("b", k));
			assertPrimitiveColumns(rec);
		}

	}

	@Test
	public void testNodeUpdateBigToSmall() throws Exception {

		Table table = fillTableBigRecs(256);

		long txId = dbh.startTransaction();

		// Update even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(0, getSmallString("a", k));
			table.putRecord(rec);
		}

		// Update odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(0, getSmallString("a", k));
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(rec.getString(0), getSmallString("a", k));
			Assert.assertEquals(rec.getString(1), getSmallString("b", k));
			assertPrimitiveColumns(rec);
		}

	}

	@Test
	public void testNodeUpdateBigToReallyBig() throws Exception {

		Table table = fillTableBigRecs(256);

		long txId = dbh.startTransaction();

		// Update even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k, 3));
			table.putRecord(rec);
		}

		// Update odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k, 3));
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(rec.getString(0), getBigString("a", k));
			Assert.assertEquals(rec.getString(1), getBigString("b", k, 3));
			assertPrimitiveColumns(rec);
		}

	}

	@Test
	public void testNodeUpdateReallyBigToReallyBig() throws Exception {

		testNodeUpdateBigToReallyBig();

		Table table = dbh.getTable("TABLE1");

		long txId = dbh.startTransaction();

		// Update even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k, 4));
			table.putRecord(rec);
		}

		// Update odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k, 4));
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(rec.getString(0), getBigString("a", k));
			Assert.assertEquals(rec.getString(1), getBigString("b", k, 4));
			assertPrimitiveColumns(rec);
		}

	}

	@Test
	public void testNodeUpdateSmallToBig() throws Exception {

		Table table = fillTableSmallRecs(256);

		long txId = dbh.startTransaction();

		// Update even keys
		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k));
			table.putRecord(rec);
		}

		// Update odd keys
		for (int k = 1; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			rec.setString(1, getBigString("b", k));
			table.putRecord(rec);
		}

		dbh.endTransaction(txId, true);

		for (int k = 0; k < 256; k += 2) {
			DBRecord rec = table.getRecord(k);
			Assert.assertEquals(rec.getString(0), getSmallString("a", k));
			Assert.assertEquals(rec.getString(1), getBigString("b", k));
			assertPrimitiveColumns(rec);
		}

	}
}
