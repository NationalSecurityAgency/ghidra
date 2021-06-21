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
package ghidra.program.database.util;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Iterator;

import org.junit.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.datastruct.IndexRange;
import ghidra.util.datastruct.IndexRangeIterator;

@SuppressWarnings("deprecation") // the SharedRangeMapDB is deprecated, but we still need to test it
public class SharedRangeMapDBTest extends AbstractGhidraHeadedIntegrationTest
		implements ErrorHandler {

	private DBHandle dbh;
	private long transactionID;

	/**
	 * Constructor for SharedRangeMapDBTest.
	 * @param arg0
	 */
	public SharedRangeMapDBTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		dbh = new DBHandle();
		transactionID = dbh.startTransaction();
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		dbh.endTransaction(transactionID, false);
		dbh.close();

	}

	/**
	 * @see db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		throw new RuntimeException(e.getMessage());
	}

	private int indexOf(Object[] list, Object item) {
		for (int i = 0; i < list.length; i++) {
			if (list[i].equals(item)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Crude inspection - assumes two records will not contain the same
	 * content.
	 * @param map
	 * @param ranges
	 * @param mapRangeToValue (from is rangeKey, to is value)
	 * @throws IOException
	 */
	private void inspectRecords(SharedRangeMapDB map, IndexRange[] ranges,
			IndexRange[] mapRangeToValue) throws IOException {

		RecordIterator iter = map.rangeTable.iterator();
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			DBRecord rec = iter.next();
			IndexRange range =
				new IndexRange(rec.getKey(), rec.getLongValue(SharedRangeMapDB.RANGE_TO_COL));
			if (indexOf(ranges, range) < 0) {
				Assert.fail("Unexpected range: " + range.getStart() + " - " + range.getEnd());
			}
		}
		assertEquals(ranges.length, cnt);

		iter = map.mapTable.iterator();
		cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			DBRecord rec = iter.next();
			IndexRange entry = new IndexRange(rec.getLongValue(SharedRangeMapDB.MAP_RANGE_KEY_COL),
				rec.getLongValue(SharedRangeMapDB.MAP_VALUE_COL));
			if (indexOf(mapRangeToValue, entry) < 0) {
				Assert.fail("Unexpected map entry: rangeKey=" + entry.getStart() + ", value=" +
					entry.getEnd());
			}
		}
		assertEquals(mapRangeToValue.length, cnt);
	}

	@Test
	public void testAdd() throws IOException {
		SharedRangeMapDB map = new SharedRangeMapDB(dbh, "TEST", this, true);

		// Add initial set of ranges
		map.add(10, 20, 1);
		map.add(30, 40, 1);
		map.add(50, 60, 1);
		map.add(70, 80, 1);

		IndexRange[] ranges = new IndexRange[] {
			new IndexRange(10, 20),
			new IndexRange(30, 40),
			new IndexRange(50, 60),
			new IndexRange(70, 80)
		};

		IndexRange[] entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(30, 1),
			new IndexRange(50, 1),
			new IndexRange(70, 1)
		};

		inspectRecords(map, ranges, entries);

		// Range already included
		map.add(52, 58, 1);
		map.add(52, 60, 1);
		map.add(50, 60, 1);

		inspectRecords(map, ranges, entries);

		// Add range
		map.add(21, 29, 1);

		ranges = new IndexRange[] {
			new IndexRange(10, 40),
			new IndexRange(50, 60),
			new IndexRange(70, 80)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(50, 1),
			new IndexRange(70, 1)
		};

		inspectRecords(map, ranges, entries);

		// Add range
		map.add(35, 55, 1);

		ranges = new IndexRange[] {
			new IndexRange(10, 60),
			new IndexRange(70, 80)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(70, 1)
		};

		inspectRecords(map, ranges, entries);

		// Add range
		map.add(55, 90, 1);

		ranges = new IndexRange[] {
			new IndexRange(10, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1)
		};

		inspectRecords(map, ranges, entries);

		// Add second overlapped value
		map.add(20, 30, 2);

		ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 30),
			new IndexRange(31, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(31, 1),
			new IndexRange(20, 2)
		};

		inspectRecords(map, ranges, entries);

		// Add third overlapped value
		map.add(28, 35, 3);

		ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 27),
			new IndexRange(28, 30),
			new IndexRange(31, 35),
			new IndexRange(36, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(28, 1),
			new IndexRange(31, 1),
			new IndexRange(36, 1),
			new IndexRange(20, 2),
			new IndexRange(28, 2),
			new IndexRange(28, 3),
			new IndexRange(31, 3)
		};

		inspectRecords(map, ranges, entries);

		// Add fourth overlapped value
		map.add(28, 35, 4);

		ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 27),
			new IndexRange(28, 30),
			new IndexRange(31, 35),
			new IndexRange(36, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(28, 1),
			new IndexRange(31, 1),
			new IndexRange(36, 1),
			new IndexRange(20, 2),
			new IndexRange(28, 2),
			new IndexRange(28, 3),
			new IndexRange(31, 3),
			new IndexRange(28, 4),
			new IndexRange(31, 4)
		};

		inspectRecords(map, ranges, entries);

		// Expand fourth overlapped value range
		map.add(25, 39, 4);

		ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 24),
			new IndexRange(25, 27),
			new IndexRange(28, 30),
			new IndexRange(31, 35),
			new IndexRange(36, 39),
			new IndexRange(40, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(25, 1),
			new IndexRange(28, 1),
			new IndexRange(31, 1),
			new IndexRange(36, 1),
			new IndexRange(40, 1),
			new IndexRange(20, 2),
			new IndexRange(25, 2),
			new IndexRange(28, 2),
			new IndexRange(28, 3),
			new IndexRange(31, 3),
			new IndexRange(25, 4),
			new IndexRange(28, 4),
			new IndexRange(31, 4),
			new IndexRange(36, 4)
		};

		inspectRecords(map, ranges, entries);
	}

	@Test
	public void testRemove() throws IOException {
		SharedRangeMapDB map = new SharedRangeMapDB(dbh, "TEST", this, true);

		// Add same entries as the testAdd used
		map.add(10, 20, 1);
		map.add(30, 40, 1);
		map.add(50, 60, 1);
		map.add(70, 80, 1);

		map.add(21, 29, 1);

		map.add(35, 55, 1);

		map.add(55, 90, 1);

		map.add(20, 30, 2);

		map.add(28, 35, 3);

		map.add(28, 35, 4);

		// Remove
		map.remove(4);

		IndexRange[] ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 27),
			new IndexRange(28, 30),
			new IndexRange(31, 35),
			new IndexRange(36, 90)
		};

		IndexRange[] entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(28, 1),
			new IndexRange(31, 1),
			new IndexRange(36, 1),
			new IndexRange(20, 2),
			new IndexRange(28, 2),
			new IndexRange(28, 3),
			new IndexRange(31, 3)
		};

		inspectRecords(map, ranges, entries);

		// Remove
		map.remove(3);

		ranges = new IndexRange[] {
			new IndexRange(10, 19),
			new IndexRange(20, 30),
			new IndexRange(31, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1),
			new IndexRange(20, 1),
			new IndexRange(31, 1),
			new IndexRange(20, 2)
		};

		inspectRecords(map, ranges, entries);

		// Remove
		map.remove(2);

		ranges = new IndexRange[] {
			new IndexRange(10, 90)
		};

		entries = new IndexRange[] {
			new IndexRange(10, 1)
		};

		inspectRecords(map, ranges, entries);

		// Remove last one
		map.remove(1);
		assertEquals(0, map.rangeTable.getRecordCount());
		assertEquals(0, map.mapTable.getRecordCount());

	}

	@Test
	public void testGetValueIterator() {
		SharedRangeMapDB map = new SharedRangeMapDB(dbh, "TEST", this, true);

		// Add same entries as the testAdd used
		map.add(10, 20, 1);
		map.add(30, 40, 1);
		map.add(50, 60, 1);
		map.add(70, 80, 1);

		map.add(21, 29, 1);

		map.add(35, 55, 1);

		map.add(55, 90, 1);

		map.add(20, 30, 2);

		map.add(28, 35, 3);

		map.add(28, 35, 4);

		// Test 1
		Iterator<Field> iter = map.getValueIterator(29, 34);
		LongField[] values = new LongField[] {
			new LongField(1),
			new LongField(2),
			new LongField(3),
			new LongField(4)
		};
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			LongField v = (LongField) iter.next();
			if (indexOf(values, v) < 0) {
				Assert.fail("Unexpected value: " + v.getLongValue());
			}
		}
		assertEquals(values.length, cnt);

		// Test 2
		iter = map.getValueIterator(0, 20);
		values = new LongField[] {
			new LongField(1),
			new LongField(2)
		};
		cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			LongField v = (LongField) iter.next();
			if (indexOf(values, v) < 0) {
				Assert.fail("Unexpected value: " + v.getLongValue());
			}
		}
		assertEquals(values.length, cnt);

		// Test 3
		iter = map.getValueIterator(89, 100);
		values = new LongField[] {
			new LongField(1)
		};
		cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			LongField v = (LongField) iter.next();
			if (indexOf(values, v) < 0) {
				Assert.fail("Unexpected value: " + v.getLongValue());
			}
		}
		assertEquals(values.length, cnt);

		// Test 4
		iter = map.getValueIterator(0, 9);
		assertTrue(!iter.hasNext());

	}

	@Test
	public void testGetValueRangeIterator() {
		SharedRangeMapDB map = new SharedRangeMapDB(dbh, "TEST", this, true);
		System.out.println("testGetValueRangeIterator ---");
		// Add same entries as the testAdd used
		map.add(10, 20, 1);
		map.add(30, 40, 1);
		map.add(50, 60, 1);
		map.add(70, 80, 1);

		map.add(21, 29, 1);

		map.add(35, 55, 1);

		map.add(55, 90, 1);

		map.add(20, 30, 2);

		map.add(28, 35, 3);

		map.add(28, 35, 4);

		map.add(25, 39, 4);

		IndexRangeIterator iter = map.getValueRangeIterator(2);
		IndexRange[] ranges = new IndexRange[] {
			new IndexRange(20, 24),
			new IndexRange(25, 27),
			new IndexRange(28, 30)
		};
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			IndexRange range = iter.next();
			if (indexOf(ranges, range) < 0) {
				Assert.fail("Unexpected range: " + range.getStart() + " - " + range.getEnd());
			}
			System.out.println("  Range: " + range.getStart() + " - " + range.getEnd());
		}
		assertEquals(ranges.length, cnt);

	}

}
