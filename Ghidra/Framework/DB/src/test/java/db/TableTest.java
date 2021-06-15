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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitorAdapter;

public class TableTest extends AbstractGenericTest {

	private static final int RECORD_KEY_SPACING = 10;
	private static final int KEY_RANGE_SIZE_PER_BUFFER = 100;

	private static final int BUFFER_SIZE = 256;
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private static final Field[] FIXED_SIZE_SCHEMA_FIELDS = new Field[] { LongField.INSTANCE,
		IntField.INSTANCE, ShortField.INSTANCE, FixedField10.INSTANCE };
	private static final Field[] VARIABLE_SIZE_SCHEMA_FIELDS =
		new Field[] { StringField.INSTANCE, };

	private static final String[] FIXED_SIZE_SCHEMA_COLUMN_NAMES =
		{ "Long1", "Int2", "Short3", "Fixed4" };
	private static final String[] VARIABLE_SIZE_SCHEMA_COLUMN_NAMES = { "String" };

	private static final Schema FIXED_SIZE_SCHEMA =
		new Schema(0, "LongKey", FIXED_SIZE_SCHEMA_FIELDS, FIXED_SIZE_SCHEMA_COLUMN_NAMES);
	private static final Schema VARIABLE_SIZE_SCHEMA =
		new Schema(0, "LongKey", VARIABLE_SIZE_SCHEMA_FIELDS, VARIABLE_SIZE_SCHEMA_COLUMN_NAMES);
	private static final int BUFFER_COUNT = 5;
	private static final int FIRST_KEY = 0;
	private static final int END_KEY = BUFFER_COUNT * 100 - 10;

	private DBHandle dbh;
	private long txId;
	private Table table;
	private List<Integer> startKeys = new ArrayList<Integer>();
	private List<Integer> endKeys = new ArrayList<Integer>();

	public TableTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		startKeys.add(getFirstRecordKeyInBuffer(0));
		startKeys.add(getInvalidKeyAfterBufferBeginning(0));

		startKeys.add(getInvalidRecordKeyBeforeBuffer(1));
		startKeys.add(getFirstRecordKeyInBuffer(1));
		startKeys.add(getInvalidKeyAfterBufferBeginning(1));
		startKeys.add(getMiddleRecordKeyInBuffer(1));
		startKeys.add(getInvalidKeyBeforeBufferEnding(1));
		startKeys.add(getLastRecordKeyInBuffer(1));

		endKeys.add(getInvalidRecordKeyBeforeBuffer(1));
		endKeys.add(getFirstRecordKeyInBuffer(1));
		endKeys.add(getInvalidKeyAfterBufferBeginning(1));
		endKeys.add(getMiddleRecordKeyInBuffer(1));
		endKeys.add(getInvalidKeyBeforeBufferEnding(1));
		endKeys.add(getLastRecordKeyInBuffer(1));
		endKeys.add(getInvalidKeyAfterBufferEnding(1));

		endKeys.add(getInvalidRecordKeyBeforeBuffer(2));
		endKeys.add(getFirstRecordKeyInBuffer(2));
		endKeys.add(getInvalidKeyAfterBufferBeginning(2));
		endKeys.add(getMiddleRecordKeyInBuffer(2));
		endKeys.add(getInvalidKeyBeforeBufferEnding(2));
		endKeys.add(getLastRecordKeyInBuffer(2));
		endKeys.add(getInvalidKeyAfterBufferEnding(2));

		endKeys.add(getFirstRecordKeyInBuffer(0));
		endKeys.add(getInvalidKeyAfterBufferBeginning(0));
		endKeys.add(getMiddleRecordKeyInBuffer(0));
		endKeys.add(getLastRecordKeyInBuffer(0));
		endKeys.add(getInvalidKeyAfterBufferEnding(0));

		endKeys.add(getInvalidRecordKeyBeforeBuffer(3));
		endKeys.add(getFirstRecordKeyInBuffer(3));
		endKeys.add(getInvalidKeyAfterBufferBeginning(3));
		endKeys.add(getMiddleRecordKeyInBuffer(3));
		endKeys.add(getInvalidKeyBeforeBufferEnding(3));
		endKeys.add(getLastRecordKeyInBuffer(3));
		endKeys.add(getInvalidKeyAfterBufferEnding(3));

		endKeys.add(getInvalidKeyBeforeBufferEnding(BUFFER_COUNT - 1));
		endKeys.add(getLastRecordKeyInBuffer(BUFFER_COUNT - 1));
		endKeys.add(getInvalidKeyAfterBufferEnding(BUFFER_COUNT - 1));

	}

	@Test
	public void testFixedSizeDeleteRecords() throws Exception {
		for (int startKey : startKeys) {
			for (int endKey : endKeys) {
				if (startKey <= endKey) {
					initializeDatabase(BUFFER_COUNT, true);
					deleteRangeAndVerify(startKey, endKey);
					closeDatabase();
				}
			}
		}
	}

	@Test
	public void testVariableSizeDeleteRecords() throws Exception {
		for (int startKey : startKeys) {
			for (int endKey : endKeys) {
				if (startKey <= endKey) {
					initializeDatabase(BUFFER_COUNT, false);
					deleteRangeAndVerify(startKey, endKey);
					closeDatabase();
				}
			}
		}
	}

//    public void testAllCombinationsWithInteriorNode() throws Exception {
//    	int bufferCount = 22;
//    	int maxKey = bufferCount*10;
//    	for(int i=0;i<maxKey;i++) {
//    		System.out.println("i = "+i);
//    		for(int j=0;j<maxKey;j++) {
//    			initializeDatabase(bufferCount, false);
//    			if (i<j) {
//	    			for(int k=i;k<=j;k++) {
//	    				table.deleteRecord(k);
//	    				assertTrue(table.isConsistent());
//	    			}
//    			}
//    			else {
//	    			for(int k=i;k>=j;k--) {
//	    				table.deleteRecord(k);
//	    				assertTrue(table.isConsistent());
//	    			}
//    			}
//				closeDatabase();
//    		}
//    	}
//    }
//    public void testRandomInsertionsPutsAndDeletions() throws IOException {
//    	Schema schema = createDatabase(false);
//    	List<Long> keyList = new ArrayList<Long>();
//    	for(int i=0;i<10000;i++) {
//    		Record record = generateRandomStringRecord(schema, keyList);
//    		table.putRecord(record);
//    	}
//		assertTrue(table.isConsistent());
//    	for(int i=0;i<30000;i++) {
//    		if (i % 1000 == 0) {
//    			System.out.println("i = "+i);
//    		}
//    		int op = (int)(Math.random() * 3);
//    		switch(op) {
//    		case 0:	// insert
//        		Record record = generateRandomStringRecord(schema, keyList);
//        		keyList.add(record.getKey());
//        		table.putRecord(record);
//        		break;
//    		case 1: // replace
//        		int index = (int)(Math.random() * keyList.size());
//        		long key = keyList.remove(index);
//        		Record record2 = schema.createRecord(key);
//        		record2.setString(0,getRandomSizeString(200) );	// this size string causes 10 records per buffer
//        		table.putRecord(record2);
//        		break;
//    		case 2: // delete
//        		index = (int)(Math.random() * keyList.size());
//        		key = keyList.remove(index);
//        		table.deleteRecord(key);
//        		break;
//    		}
//    		assertTrue(table.isConsistent());
//    	}
//    	while(!keyList.isEmpty()) {
//    		int index = (int)(Math.random() * keyList.size());
//    		long key = keyList.remove(index);
//    		System.out.println("Deleting "+key);
//    		table.deleteRecord(key);
//    		assertTrue(table.isConsistent());
//    	}
//    }
//    public void testIteratorDeletion() throws Exception {
//    	Schema schema = createDatabase(false);
//    	List<Long> keyList = new ArrayList<Long>();
//    	for(int i=0;i<10000;i++) {
//    		Record record = generateRandomStringRecord(schema, keyList);
//    		table.putRecord(record);
//    	}
//    	for(int i=0;i<1000;i++) {
//    		long startKey = (long)(Math.random() * 1000000000F);
//    		int numRecordsToDelete = (int)(Math.random() * 30);
//    		RecordIterator iterator = table.iterator(startKey);
//    		for(int j =0;j<numRecordsToDelete;j++) {
//    			System.out.println("i = "+i+",  j = "+j);
//    			if (iterator.hasNext()) {
//	    			iterator.next();
//	    			iterator.delete();
//	    			assertTrue(table.isConsistent());
//    			}
//    			else {
//    				break;
//    			}
//    		}
//    		
//    	}
//    }
	private DBRecord generateRandomStringRecord(Schema schema, List<Long> keyList) {
		long key = (long) (Math.random() * 1000000000F);
		keyList.add(key);
		DBRecord record = schema.createRecord(key);
		record.setString(0, getRandomSizeString(200));// this size string causes 10 records per buffer
		return record;
	}

//    public void testRandomPutsOfVariousSizeData() throws IOException {
//    	Schema schema = createDatabase(false);
//    	List<Long> keyList = new ArrayList<Long>();
//    	for(int i=0;i<10000;i++) {
//    		long key = i;
//    		keyList.add(key);
//    		Record record = schema.createRecord(key);
//    		record.setString(0,getRandomSizeString(200) );
//    		table.putRecord(record);
//    	}
//		assertTrue(table.isConsistent());
//    	for(int i=0;i<10000;i++) {
//    		System.out.println("i = "+i);
//    		long key = (long)(Math.random() * 10000L);
//    		Record record = schema.createRecord(key);
//    		record.setString(0,getRandomSizeString(200) );
//    		table.putRecord(record);
//    		assertTrue(table.isConsistent());
//    	}
//
//    }
	private String getRandomSizeString(int max) {
		int size = (int) (Math.random() * max);
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < size; i++) {
			buf.append(' ');
		}
		return buf.toString();
	}

	private void initializeDatabase(int bufferCount, boolean fixedSize) throws Exception {
		Schema schema = createDatabase(fixedSize);

		int n = bufferCount * RECORD_KEY_SPACING;
		for (int i = 0; i < n; i++) {
			DBRecord rec = schema.createRecord(i * RECORD_KEY_SPACING);
			if (fixedSize) {
				rec.setLongValue(0, i);
				rec.setIntValue(1, i);
				rec.setShortValue(2, (short) i);
				rec.setField(3, FixedField10.INSTANCE.getMaxValue());
			}
			else {
				rec.setString(0, "abcdef");
			}
			table.putRecord(rec);
		}
	}

	private Schema createDatabase(boolean fixedSize) throws IOException {
		dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
		txId = dbh.startTransaction();

		Schema schema = fixedSize ? FIXED_SIZE_SCHEMA : VARIABLE_SIZE_SCHEMA;
		table = dbh.createTable("TableTestTable", schema);
		return schema;
	}

	private void closeDatabase() throws Exception {
		dbh.endTransaction(txId, false);
		dbh.close();
	}

	private int getFirstRecordKeyInBuffer(int bufferIndex) {
		return KEY_RANGE_SIZE_PER_BUFFER * bufferIndex;
	}

	private int getInvalidRecordKeyBeforeBuffer(int bufferIndex) {
		return getFirstRecordKeyInBuffer(bufferIndex) - 1;
	}

	private int getInvalidKeyAfterBufferBeginning(int bufferIndex) {
		return getFirstRecordKeyInBuffer(bufferIndex) + 1;
	}

	private int getMiddleRecordKeyInBuffer(int bufferIndex) {
		// 10 records per buffer; pick one in the middle
		int middleRecordOffset = 5 * RECORD_KEY_SPACING;
		return getFirstRecordKeyInBuffer(bufferIndex) + middleRecordOffset;
	}

	private int getLastRecordKeyInBuffer(int bufferIndex) {
		return getFirstRecordKeyInBuffer(bufferIndex) +
			(KEY_RANGE_SIZE_PER_BUFFER - RECORD_KEY_SPACING);
	}

	private int getInvalidKeyBeforeBufferEnding(int bufferIndex) {
		return getLastRecordKeyInBuffer(bufferIndex) - 1;
	}

	private int getInvalidKeyAfterBufferEnding(int bufferIndex) {
		return getLastRecordKeyInBuffer(bufferIndex) + 1;
	}

	private void deleteRangeAndVerify(int startKey, int endKey) throws Exception {
		assertTrue(table.deleteRecords(startKey, endKey));

		verifyRangeDoesNotExist(startKey, endKey);
		verifyRecordsBeforeAndAfterExist(startKey, endKey);
		assertTrue(table.isConsistent(TaskMonitorAdapter.DUMMY_MONITOR));
	}

	private void verifyRangeDoesNotExist(int startKey, int endKey) throws IOException {
		for (int i = startKey; i <= endKey; i++) {
			assertNull(table.getRecord(i));
		}
	}

	private void verifyRecordsBeforeAndAfterExist(int startKey, int endKey) throws IOException {
		int validKeyBeforeKey = getKeyBeforeKey(startKey);
		int validKeyAfterKey = getKeyAfterKey(endKey);

		if (startKey > FIRST_KEY) {
			assertNotNull(table.getRecord(validKeyBeforeKey));
		}
		if (endKey < END_KEY) {
			assertNotNull("startKey = " + startKey + ", endkey = " + endKey,
				table.getRecord(validKeyAfterKey));
		}
	}

	private int getKeyAfterKey(int fromKey) {
		return ((fromKey / RECORD_KEY_SPACING) + 1) * RECORD_KEY_SPACING;
	}

	private int getKeyBeforeKey(int fromKey) {
		return ((fromKey - 1) / RECORD_KEY_SPACING) * RECORD_KEY_SPACING;
	}
}
