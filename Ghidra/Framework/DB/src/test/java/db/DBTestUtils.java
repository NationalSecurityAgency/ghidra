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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

import org.junit.Assert;

import db.buffers.BufferFileManager;
import db.buffers.DummyBufferFileMgr;

/**
 *
 */
public class DBTestUtils {

	// Schema Types
	static final int EMPTY = 0;
	static final int SINGLE_BOOLEAN = 1;
	static final int SINGLE_BYTE = 2;
	static final int SINGLE_INT = 3;
	static final int SINGLE_SHORT = 4;
	static final int SINGLE_LONG = 5;
	static final int SINGLE_STRING = 6;
	static final int SINGLE_BINARY = 7;
	static final int SINGLE_FIXED = 8;
	static final int ALL_FIXED = 9;
	static final int ALL_TYPES = 10;

	static final int MAX_SCHEMA_TYPE = 10;

	//@formatter:off
	private static final Field[][] schemaFields = { 
		{}, // no columns
		{ BooleanField.INSTANCE },
		{ ByteField.INSTANCE }, 
		{ IntField.INSTANCE }, 
		{ ShortField.INSTANCE },
		{ LongField.INSTANCE }, 
		{ StringField.INSTANCE }, 
		{ BinaryField.INSTANCE },
		{ FixedField10.INSTANCE },
		{ BooleanField.INSTANCE, ByteField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE, 
			LongField.INSTANCE, FixedField10.INSTANCE },
		{ BooleanField.INSTANCE, ByteField.INSTANCE, IntField.INSTANCE, ShortField.INSTANCE, 
			LongField.INSTANCE, StringField.INSTANCE, BinaryField.INSTANCE, FixedField10.INSTANCE } };
	//@formatter:on

	private static final int[][] schemaIndexedColumns =
		{ {}, {}, {}, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 2, 3, 4, 5 },
			{ 2, 3, 4, 5, 6, 7 } };

	//@formatter:off
	private static final String[][] schemaFieldNames = { 
		{}, // no columns
		{ "Boolean" }, { "Byte" }, { "Int" }, { "Short" }, { "Long" }, 
		{ "String" }, { "Binary" }, { "Fixed" },
		{ "Boolean", "Byte", "Int", "Short", "Long", "Fixed" },
		{ "Boolean", "Byte", "Int", "Short", "Long", "String", "Binary", "Fixed" } 
	};
	//@formatter:on

	private static final Schema[] longKeySchemas;
	static {
		longKeySchemas = new Schema[MAX_SCHEMA_TYPE + 1];
		for (int i = 0; i < longKeySchemas.length; i++) {
			longKeySchemas[i] = new Schema(0, "LongKey", schemaFields[i], schemaFieldNames[i]);
		}
	}

	private static final Field fixedKeyType = new FixedField10();

	private static final Schema[] fixedKeySchemas;
	static {
		fixedKeySchemas = new Schema[MAX_SCHEMA_TYPE + 1];
		for (int i = 0; i < fixedKeySchemas.length; i++) {
			fixedKeySchemas[i] =
				new Schema(0, fixedKeyType, "FixedKey", schemaFields[i], schemaFieldNames[i]);
		}
	}

	private static final Field varKeyType = new BinaryField();

	private static final Schema[] binaryKeySchemas;
	static {
		binaryKeySchemas = new Schema[MAX_SCHEMA_TYPE + 1];
		for (int i = 0; i < binaryKeySchemas.length; i++) {
			binaryKeySchemas[i] =
				new Schema(0, varKeyType, "VarKey", schemaFields[i], schemaFieldNames[i]);
		}
	}

	static Random random = new Random(0x123456789L);

	static int[] getIndexedColumns(int schemaType) {
		return schemaIndexedColumns[schemaType];
	}

	static int getIndexedColumnCount(int schemaType) {
		return schemaIndexedColumns[schemaType].length;
	}

	/**
	 * Create a new long-keyed table within the specified database.
	 * @param db database handle
	 * @param name name of table
	 * @param schemaType type of schema (use static identifier)
	 * @param createIndex all fields will be indexed if true
	 * @param useSparseColumns all fields will use sparse storage if true
	 * @return Table new table
	 * @throws IOException
	 */
	static Table createLongKeyTable(DBHandle db, String name, int schemaType, boolean createIndex,
			boolean useSparseColumns)
			throws IOException {
		Table t;
		int indexCnt = 0;
		int[] indexedColumns = null;

		Schema[] schemas = longKeySchemas.clone();
		if (useSparseColumns) {
			for (int i = 0; i < schemas.length; i++) {
				schemas[i] = createSparseSchema(schemas[i]);
			}
		}

		if (createIndex) {
			indexCnt = getIndexedColumnCount(schemaType);
			indexedColumns = getAllowedIndexColumns(schemaFields[schemaType]);
		}

		t = db.createTable(name, schemas[schemaType], indexedColumns);

		Assert.assertEquals(name, t.getName());
		Assert.assertEquals(indexCnt, t.getIndexedColumns().length);
		Assert.assertEquals(Long.MIN_VALUE, t.getMaxKey());
		Assert.assertEquals(0, t.getRecordCount());
		Assert.assertEquals(schemas[schemaType], t.getSchema());
		Assert.assertTrue(t.useLongKeys());
		return t;
	}

	private static Schema createSparseSchema(Schema schema) {

		Field[] fields = schema.getFields();
		int[] sparseColumnIndexes = new int[fields.length];
		for (int i = 0; i < sparseColumnIndexes.length; i++) {
			sparseColumnIndexes[i] = i;
		}
		return new Schema(schema.getVersion(), schema.getKeyFieldType(), schema.getKeyName(),
			fields, schema.getFieldNames(), sparseColumnIndexes);
	}

	static int[] getAllowedIndexColumns(Field[] columnFields) {
		ArrayList<Integer> list = new ArrayList<>();
		for (int i = 0; i < columnFields.length; i++) {
			if (Field.canIndex(columnFields[i])) {
				list.add(i);
			}
		}
		int[] columnIndexes = new int[list.size()];
		for (int i = 0; i < columnIndexes.length; i++) {
			columnIndexes[i] = list.get(i);
		}
		return columnIndexes;
	}

	/**
	 * Create a new FixedField-keyed table within the specified database.
	 * @param db database handle
	 * @param name name of table
	 * @param schemaType type of schema (use static identifier)
	 * @param createIndex all fields will be indexed if true
	 * @param useSparseColumns all fields will use sparse storage if true
	 * @return Table new table
	 * @throws IOException
	 */
	static Table createFixedKeyTable(DBHandle db, String name, int schemaType, boolean createIndex,
			boolean useSparseColumns)
			throws IOException {
		Table t;
		int indexCnt = 0;
		int[] indexedColumns = null;

		Schema[] schemas = fixedKeySchemas.clone();
		if (useSparseColumns) {
			for (int i = 0; i < schemas.length; i++) {
				schemas[i] = createSparseSchema(schemas[i]);
			}
		}

		if (createIndex) {
			indexCnt = getIndexedColumnCount(schemaType);
			indexedColumns = getAllowedIndexColumns(schemaFields[schemaType]);
		}

		t = db.createTable(name, schemas[schemaType], indexedColumns);

		if (createIndex) {
			Assert.assertArrayEquals(schemaIndexedColumns[schemaType], t.getIndexedColumns());
		}

		Assert.assertEquals(name, t.getName());
		Assert.assertEquals(indexCnt, t.getIndexedColumns().length);
		Assert.assertEquals(Long.MIN_VALUE, t.getMaxKey());
		Assert.assertEquals(0, t.getRecordCount());
		Assert.assertEquals(schemas[schemaType], t.getSchema());
		Assert.assertTrue(!t.useLongKeys());
		return t;
	}

	/**
	 * Create a new BinaryField-keyed table within the specified database.
	 * @param db database handle
	 * @param name name of table
	 * @param schemaType type of schema (use static identifier)
	 * @param createIndex all fields will be indexed if true
	 * @return Table new table
	 * @throws IOException
	 */
	static Table createBinaryKeyTable(DBHandle db, String name, int schemaType, boolean createIndex)
			throws IOException {
		Table t;
		int indexCnt = 0;
		if (createIndex) {
			int[] indexedColumns = getAllowedIndexColumns(schemaFields[schemaType]);
			t = db.createTable(name, binaryKeySchemas[schemaType], indexedColumns);
		}
		else {
			t = db.createTable(name, binaryKeySchemas[schemaType]);
		}
		Assert.assertEquals(name, t.getName());
		Assert.assertEquals(indexCnt, t.getIndexedColumns().length);
		Assert.assertEquals(Long.MIN_VALUE, t.getMaxKey());
		Assert.assertEquals(0, t.getRecordCount());
		Assert.assertEquals(binaryKeySchemas[schemaType], t.getSchema());
		Assert.assertTrue(!t.useLongKeys());
		return t;
	}

	static String[] getFieldNames(int schemaType) {
		return schemaFieldNames[schemaType];
	}

	static int getRandomKeyLength(int maxLength) {
		return random.nextInt(maxLength) + 1;
	}

	/**
	 * Create a new long-keyed record.
	 * @param table table
	 * @param randomKey use a random key if true, else use the next avaiable key
	 * @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 */
	static DBRecord createLongKeyRecord(Table table, boolean randomKey, int varDataSize,
			boolean doInsert) throws IOException, DuplicateKeyException {
		long key;
		if (randomKey) {
			key = random.nextLong();
		}
		else {
			key = table.getMaxKey() + 1;
		}
		try {
			DBRecord rec = createRecord(table, key, varDataSize, doInsert);
			if (!randomKey) {
				Assert.assertEquals(rec.getKey(), table.getMaxKey());
			}
			return rec;
		}
		catch (DuplicateKeyException dke) {
			if (randomKey) {
				return createLongKeyRecord(table, randomKey, varDataSize, doInsert);
			}
			throw dke;
		}
	}

	/**
	 * Create a new random-FixedField-keyed record.
	 * @param table
	 * @param varDataSize
	 * @param doInsert
	 * @return Record
	 * @throws IOException
	 * @throws DuplicateKeyException
	 */
	static DBRecord createFixedKeyRecord(Table table, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		int keyLength = 10;
		byte[] bytes = new byte[keyLength];
		random.nextBytes(bytes);
		Field key = fixedKeyType.newField();
		key.setBinaryData(bytes);

		try {
			DBRecord rec = createRecord(table, key, varDataSize, doInsert);
			Assert.assertEquals(key, rec.getKeyField());
			return rec;
		}
		catch (DuplicateKeyException dke) {
			return createFixedKeyRecord(table, varDataSize, doInsert);
		}
	}

	/**
	 * Create a new random-BinaryField-keyed record.
	 * @param table
	 * @param maxKeyLength maximum key length; if < 0 keyLength = -maxKeyLength
	 * @param varDataSize
	 * @param doInsert
	 * @return Record
	 * @throws IOException
	 * @throws DuplicateKeyException
	 */
	static DBRecord createBinaryKeyRecord(Table table, int maxKeyLength, int varDataSize,
			boolean doInsert) throws IOException, DuplicateKeyException {
		int keyLength =
			(maxKeyLength < 0) ? -maxKeyLength : DBTestUtils.getRandomKeyLength(maxKeyLength);
		byte[] bytes = new byte[keyLength];
		random.nextBytes(bytes);
		Field key = varKeyType.newField();
		key.setBinaryData(bytes);

		try {
			DBRecord rec = createRecord(table, key, varDataSize, doInsert);
			Assert.assertEquals(key, rec.getKeyField());
			return rec;
		}
		catch (DuplicateKeyException dke) {
			return createBinaryKeyRecord(table, maxKeyLength, varDataSize, doInsert);
		}
	}

	/**
	 * Create a new record.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static DBRecord createRecord(Table table, long key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			DBRecord oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		DBRecord rec = table.getSchema().createRecord(key);
		fillRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Create a new record.  Only use with Long Key tables.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static DBRecord createRecord(Table table, Field key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			DBRecord oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		DBRecord rec = table.getSchema().createRecord(key);
		fillRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	static FixedField addToFixedField(Field fixedField, long increment) {
		FixedField f = (FixedField) fixedField;
		byte[] valueBytes = f.getBinaryData();
		BigInteger v = new BigInteger(1, valueBytes);
		v = v.add(BigInteger.valueOf(increment));
		byte[] resultBytes = v.toByteArray();
		if (resultBytes.length > valueBytes.length) {
			if (resultBytes[0] != 0) {
				throw new UnsupportedOperationException("overflow in test data");
			}
			byte[] b = new byte[valueBytes.length];
			System.arraycopy(resultBytes, 1, b, 0, valueBytes.length);
			resultBytes = b;
		}
		else if (resultBytes.length < valueBytes.length) {
			byte[] b = new byte[valueBytes.length];
			System.arraycopy(resultBytes, 0, b, valueBytes.length - resultBytes.length,
				resultBytes.length);
			resultBytes = b;
		}
		FixedField r = f.newField();
		r.setBinaryData(resultBytes);
		return r;
	}

	/**
	 * Create a new record whose value is in the center portion of the valid
	 * values range for byte, short, int, or long.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static DBRecord createMidRangeRecord(Table table, long key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			DBRecord oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		DBRecord rec = table.getSchema().createRecord(key);
		fillMidRangeRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Create a new record whose value is in the center portion of the valid
	 * values range for byte, short, int, or long.  Only use with Long Key tables.
	 * @param table table
	 * @param key record key
	 *  @param varDataSize number of bytes created for all variable length fields
	 * @param doInsert insert record into table if true
	 * @return Record new record
	 * @throws IOException
	 * @throws DuplicateKeyException record with assigned key already exists in table.
	 */
	static DBRecord createMidRangeRecord(Table table, Field key, int varDataSize, boolean doInsert)
			throws IOException, DuplicateKeyException {
		// Check for duplicate key
		if (doInsert) {
			DBRecord oldRec = table.getRecord(key);
			if (oldRec != null) {
				throw new DuplicateKeyException();
			}
		}

		// Create record and fill with data
		DBRecord rec = table.getSchema().createRecord(key);
		fillMidRangeRecord(rec, varDataSize);

		// Insert record if requested
		if (doInsert) {
			int cnt = table.getRecordCount();
			table.putRecord(rec);
			Assert.assertEquals(1, table.getRecordCount() - cnt);
		}

		return rec;
	}

	/**
	 * Fill record with random data.
	 * @param rec record
	 * @param varDataSize number of bytes to fill into all variable length fields.
	 * NOTE: The StringField does not strictly follow the varDataSize paramter.
	 * A value less than 0 results in a null assignment to those fields.
	 */
	static void fillRecord(DBRecord rec, int varDataSize) {

		Field[] fields = rec.getFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i] instanceof BooleanField) {
				rec.setBooleanValue(i, (random.nextInt() % 2) == 0);
			}
			else if (fields[i] instanceof ByteField) {
				rec.setByteValue(i, (byte) random.nextInt());
			}
			else if (fields[i] instanceof ShortField) {
				rec.setShortValue(i, (short) random.nextInt());
			}
			else if (fields[i] instanceof IntField) {
				rec.setIntValue(i, random.nextInt());
			}
			else if (fields[i] instanceof LongField) {
				rec.setLongValue(i, random.nextLong());
			}
			else if (fields[i] instanceof StringField) {
				int size = varDataSize;
				if (size < 0) {
					size = random.nextInt(6) - 1;
				}
				if (size < 0) {
					rec.setString(i, null);
				}
				else {
					char[] chars = new char[size];
					for (int n = 0; n < chars.length; n++) {
						chars[n] = (char) (random.nextInt() & 0x7fff);
					}
					String str = new String(chars);
					rec.setString(i, str);
				}
			}
			else if (fields[i] instanceof BinaryField) {
				int size = fields[i].isVariableLength() ? varDataSize : fields[i].length();
				if (size < 0) {
					size = random.nextInt(6) - 1;
				}
				if (size < 0) {
					rec.setBinaryData(i, null);
				}
				else {
					byte[] bytes = new byte[size];
					random.nextBytes(bytes);
					rec.setBinaryData(i, bytes);
				}
			}
			else {
				Assert.fail();
			}
		}

	}

	/**
	 * Fill record with random data that falls int the middle range for
	 * the value type. The middle range is considered form half the min value
	 * to half the max value. It only applies to byte, short, int, and long currently.
	 * @param rec record
	 * @param varDataSize number of bytes to fill into all variable length fields.
	 * A value less than 0 results in a null assignment to those fields.
	 */
	static void fillMidRangeRecord(DBRecord rec, int varDataSize) {

		Field[] fields = rec.getFields();
		for (int i = 0; i < fields.length; i++) {
			if (fields[i] instanceof ByteField) {
				rec.setByteValue(i,
					getRandomByte((byte) (Byte.MIN_VALUE / 2), (byte) (Byte.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof ShortField) {
				rec.setShortValue(i,
					getRandomShort((short) (Short.MIN_VALUE / 2), (short) (Short.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof IntField) {
				rec.setIntValue(i, getRandomInt((Integer.MIN_VALUE / 2), (Integer.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof LongField) {
				rec.setLongValue(i, getRandomLong((Long.MIN_VALUE / 2), (Long.MAX_VALUE / 2)));
			}
			else if (fields[i] instanceof StringField) {
				if (varDataSize < 0) {
					rec.setString(i, null);
				}
				else {
					char[] chars = new char[varDataSize / 2];
					for (int n = 0; n < chars.length; n++) {
						chars[n] =
							(char) (getRandomInt((Integer.MIN_VALUE / 2), (Integer.MAX_VALUE / 2)) &
								0x7fff);
					}
					String str = new String(chars);
					rec.setString(i, str);
				}
			}
			else if (fields[i] instanceof BinaryField) {
				if (varDataSize < 0) {
					rec.setBinaryData(i, null);
				}
				else {
					byte[] bytes = new byte[varDataSize];
					random.nextBytes(bytes);
					rec.setBinaryData(i, bytes);
				}
			}
			else {
				Assert.fail();
			}
		}

	}

	static byte getRandomByte(byte min, byte max) {
		byte value = 0;
		do {
			value = (byte) random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static short getRandomShort(short min, short max) {
		short value = 0;
		do {
			value = (short) random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static int getRandomInt(int min, int max) {
		int value = 0;
		do {
			value = random.nextInt();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static long getRandomLong(long min, long max) {
		long value = 0;
		do {
			value = random.nextLong();
		}
		while ((value < min) || (value > max));
		return value;
	}

	static BinaryField increment(BinaryField field, int maxLength) {

		byte[] bytes = field.getBinaryData();
		if (bytes == null) {
			return new BinaryField(new byte[0]);
		}

		int len = bytes.length;
		byte[] newBytes;
		if (len < maxLength) {
			// Simply increase length by adding trailing 0 byte
			newBytes = new byte[len + 1];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			newBytes[len] = (byte) 0x00;
		}
		else if (bytes[len - 1] == (byte) 0xff) {
			// chop trailing ff bytes, increment new last byte
			int newLen = len;
			while (newLen > 0 && bytes[newLen - 1] == (byte) 0xff) {
				--newLen;
			}
			newBytes = new byte[newLen];
			System.arraycopy(bytes, 0, newBytes, 0, newLen);
			if (newLen > 0) {
				++newBytes[newLen - 1];
			}
			else {
				// wrap error
				Assert.fail("Bad test data: attempt to increment max value");
			}
		}
		else {
			// increment last byte only
			newBytes = new byte[len];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			++newBytes[len - 1];
		}
		return new BinaryField(newBytes);
	}

	static BinaryField decrement(BinaryField field, int maxLength) {

		byte[] bytes = field.getBinaryData();
		if (bytes == null) {
			Assert.fail("Bad test data: attempt to deccrement min value ");
		}

		int len = bytes.length;
		if (len == 0) {
			return new BinaryField(null);
		}
		byte[] newBytes;
		if (bytes[len - 1] == 0) {
			// chop trailing 00 byte
			newBytes = new byte[len - 1];
			System.arraycopy(bytes, 0, newBytes, 0, len - 1);
		}
		else if (len < maxLength) {
			// Simply create maximum length value with trailing ff's
			newBytes = new byte[maxLength];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			--newBytes[len - 1];
			for (int i = len; i < maxLength; i++) {
				newBytes[i] = (byte) 0xff;
			}
		}
		else {
			// decrement last byte only
			newBytes = new byte[len];
			System.arraycopy(bytes, 0, newBytes, 0, len);
			--newBytes[len - 1];
		}
		return new BinaryField(newBytes);
	}

	static BinaryField getMaxValue(int maxLength) {
		byte[] bytes = new byte[maxLength];
		for (int i = 0; i < maxLength; i++) {
			bytes[i] = (byte) 0xff;
		}
		return new BinaryField(bytes);
	}

	public static void main(String[] args) {

		int maxLen = 3;

		System.out.println("Incrementing...");
		BinaryField bf = new BinaryField(null);
		BinaryField lastBf = bf;
		int cnt = 0;
		try {
			while (true) {
				bf = increment(bf, maxLen);
//				System.out.println(bf.toString());
				if (bf.compareTo(lastBf) <= 0) {
					System.out.println("Failed: " + bf + " is not greater than " + lastBf);
					System.exit(-1);
				}
				lastBf = bf;
				++cnt;
			}
		}
		catch (Exception e) {
//			e.printStackTrace();
		}
		System.out.println("Incremented " + cnt + " values");

		System.out.println("Decrementing...");
		cnt = 0;
		try {
			while (true) {
				bf = decrement(bf, maxLen);
//				System.out.println(bf.toString());
				if (bf.compareTo(lastBf) >= 0) {
					System.out.println("Failed: " + bf + " is not less than " + lastBf);
					System.exit(-1);
				}
				lastBf = bf;
				++cnt;
			}
		}
		catch (Exception e) {
//			e.printStackTrace();
		}
		System.out.println("Decremented " + cnt + " values");
	}

	static BufferFileManager getBufferFileManager(File dir, String dbName) {
		return new DummyBufferFileMgr(dir, dbName, false, false);
	}
}

class DuplicateKeyException extends Exception {

	DuplicateKeyException() {
		super();
	}

}
