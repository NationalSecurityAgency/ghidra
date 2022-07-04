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
package ghidra.program.database.map;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import db.Field;
import db.LongField;
import db.util.ErrorHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractAddressRangeMapTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env; // needed to discover languages
	private ProgramDB program;
	private AddressMapDB addrMap;
	private AddressSpace space;
	private int txId;

	protected static Field ONE = new LongField(1);
	protected static Field TWO = new LongField(2);
	protected AddressRangeMapDB map;
	protected Address spaceMax;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		program = createProgram();
		MemoryMapDB memory = program.getMemory();
		addrMap = (AddressMapDB) getInstanceField("addrMap", memory);
		space = program.getAddressFactory().getDefaultAddressSpace();
		spaceMax = space.getMaxAddress();
		ErrorHandler errHandler = e -> fail();

		map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", errHandler, LongField.INSTANCE, true);
		txId = program.startTransaction("test");
	}

	protected abstract ProgramDB createProgram() throws IOException;

	@After
	public void tearDown() {
		program.endTransaction(txId, false);
		if (program != null) {
			program.release(this);
		}
		addrMap = null;
		env.dispose();
	}

	protected Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testPaint() {
		map.paintRange(addr(0x100), addr(0x200), ONE);
		map.paintRange(addr(0x300), addr(0x400), TWO);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x100), addr(0x200)), ranges.get(0));
		assertEquals(range(addr(0x300), addr(0x400)), ranges.get(1));

		checkRange(ranges.get(0), ONE);
		checkRange(ranges.get(1), TWO);
	}

	@Test
	public void testPaintOverlap() {
		assertNull(map.getValue(addr(0x200)));

		map.paintRange(addr(0x100), addr(0x300), ONE);
		map.paintRange(addr(0x200), addr(0x400), TWO);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x100), addr(0x1ff)), ranges.get(0));
		assertEquals(range(addr(0x200), addr(0x400)), ranges.get(1));

		checkRange(ranges.get(0), ONE, null, TWO);
		checkRange(ranges.get(1), TWO, ONE, null);
	}

	@Test
	public void testPaintCoallesceWithLowerSuccessorRange() {
		map.paintRange(addr(0x100), addr(0x1ff), ONE);
		map.paintRange(addr(0x200), addr(0x300), ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x100), addr(0x300)), ranges.get(0));

		checkRange(ranges.get(0), ONE);
	}

	@Test
	public void testPaintCoallesceWithHigherExistingRange() {
		map.paintRange(addr(0x200), addr(0x300), ONE);
		map.paintRange(addr(0x100), addr(0x1ff), ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x100), addr(0x300)), ranges.get(0));

		checkRange(ranges.get(0), ONE);
	}

	@Test
	public void testPaintCoallesceWithLowerOverlappingRange() {
		map.paintRange(addr(0x100), addr(0x300), ONE);
		map.paintRange(addr(0x200), addr(0x400), ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x100), addr(0x400)), ranges.get(0));

		checkRange(ranges.get(0), ONE);
	}

	@Test
	public void testPaintCoallesceWithHigherOverlappingRange() {
		map.paintRange(addr(0x200), addr(0x400), ONE);
		map.paintRange(addr(0x100), addr(0x300), ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x100), addr(0x400)), ranges.get(0));

		checkRange(ranges.get(0), ONE);
	}

	@Test
	public void testPaintSplitExistingRangeWithNewValue() {
		map.paintRange(addr(0x100), addr(0x400), ONE);
		map.paintRange(addr(0x200), addr(0x300), TWO);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(3, ranges.size());
		assertEquals(range(addr(0x100), addr(0x1ff)), ranges.get(0));
		assertEquals(range(addr(0x200), addr(0x300)), ranges.get(1));
		assertEquals(range(addr(0x301), addr(0x400)), ranges.get(2));

		checkRange(ranges.get(0), ONE, null, TWO);
		checkRange(ranges.get(1), TWO, ONE, ONE);
		checkRange(ranges.get(2), ONE, TWO, null);

	}

	@Test
	public void testPaintStartOfExitingRangeWithNewValue() {
		map.paintRange(addr(0x200), addr(0x400), ONE);
		map.paintRange(addr(0x100), addr(0x300), TWO);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x100), addr(0x300)), ranges.get(0));
		assertEquals(range(addr(0x301), addr(0x400)), ranges.get(1));

		checkRange(ranges.get(0), TWO, null, ONE);
		checkRange(ranges.get(1), ONE, TWO, null);
	}

	@Test
	public void testPaintSameValueInsideExistingRange() {
		map.paintRange(addr(0x100), addr(0x200), ONE);
		map.paintRange(addr(0x110), addr(0x150), ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x100), addr(0x200)), ranges.get(0));

		checkRange(ranges.get(0), ONE);
	}

	@Test
	public void testGetValueRecordWithStartKeyGreaterThanEndKey() {
		addrMap.setImageBase(addr(0x100));
		// address 0 will have a high key, and address 0x200 will have a low key
		map.paintRange(addr(0), addr(0x200), ONE);

		checkValueNoCache(ONE, addr(0x0));
		checkValueNoCache(ONE, addr(0x1));
		checkValueNoCache(ONE, addr(0xff));
		checkValueNoCache(ONE, addr(0x100));
		checkValueNoCache(ONE, addr(0x101));
		checkValueNoCache(ONE, addr(0x1ff));
		checkValueNoCache(ONE, addr(0x200));
		checkValueNoCache(null, addr(0x201));
		checkValueNoCache(null, spaceMax);
	}

	@Test
	public void testGetValueWithWrappingAddressRecordAndStartKeyGreaterThanEndKey() {
		addrMap.setImageBase(addr(0x200));
		// address 0 will have a high key, and address 0x200 will have a low key
		map.paintRange(addr(0), addr(0x400), ONE);
		addrMap.setImageBase(addr(0x100));
		map.invalidate();

		checkValueNoCache(ONE, addr(0x0));
		checkValueNoCache(ONE, addr(0xff));
		checkValueNoCache(ONE, addr(0x100));
		checkValueNoCache(ONE, addr(0x101));
		checkValueNoCache(ONE, addr(0x1ff));
		checkValueNoCache(ONE, addr(0x200));
		checkValueNoCache(ONE, addr(0x201));
		checkValueNoCache(ONE, addr(0x2ff));
		checkValueNoCache(ONE, addr(0x300));
		checkValueNoCache(null, addr(0x301));
		checkValueNoCache(null, addr(0).subtractWrap(0x101));
		checkValueNoCache(ONE, addr(0).subtractWrap(0x100));
		checkValueNoCache(ONE, addr(0).subtractWrap(0x0ff));
		checkValueNoCache(ONE, spaceMax);
	}

	protected void checkValueNoCache(Field expectedValue, Address address) {
		map.invalidate(); // clears  cache
		assertEquals(expectedValue, map.getValue(address));
	}

	@Test
	public void testGetRecordCount() {
		assertEquals(0, map.getRecordCount());

		map.paintRange(addr(0x100), addr(0x200), ONE);
		assertEquals(1, map.getRecordCount());

		map.paintRange(addr(0x300), addr(0x400), ONE);
		assertEquals(2, map.getRecordCount());

		// paint the gap should result in only 1 record
		map.paintRange(addr(0x200), addr(0x300), ONE);
		assertEquals(1, map.getRecordCount());
	}

	@Test
	public void testMoveAddressRange() throws CancelledException {
		map.paintRange(addr(0x100), addr(0x300), ONE);

		map.moveAddressRange(addr(0x200), addr(0x500), 0x200, TaskMonitor.DUMMY);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x100), addr(0x1ff)), ranges.get(0));
		assertEquals(range(addr(0x500), addr(0x600)), ranges.get(1));

		checkRange(ranges.get(0), ONE);
		checkRange(ranges.get(1), ONE);
	}

	@Test
	public void testIsEmpty() {
		assertTrue(map.isEmpty());

		map.paintRange(addr(0x100), addr(0x900), ONE);
		assertFalse(map.isEmpty());

		map.clearRange(addr(0), addr(0x1000));
		assertTrue(map.isEmpty());
	}

	@Test
	public void testPaintFullRangeWithNonZeroImageBase() {
		Address imageBase = addr(0x50);

		addrMap.setImageBase(imageBase);

		AddressRange range = range(space.getMinAddress(), space.getMaxAddress());
		map.paintRange(range.getMinAddress(), range.getMaxAddress(), ONE);

		assertEquals(ONE, map.getValue(addr(0)));
		assertEquals(ONE, map.getValue(addr(0x200)));
		assertEquals(ONE, map.getValue(space.getMaxAddress()));

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range, ranges.get(0));
	}

	@Test
	public void testAddressRangeIteratorWithNoTable() {
		AddressRangeIterator it = map.getAddressRanges();
		assertFalse(it.hasNext());
	}

	@Test
	public void testIteratorWithMultipleRangesIncludeOneThatSpansAddressBoundary() {

		Address imageBase = addr(0x100);

		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(spaceMax.subtract(0x500), spaceMax);

		addrMap.setImageBase(imageBase);
		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		checkRange(range1, ONE);
		checkRange(range2, ONE);
		checkRange(range3, ONE);
		checkRange(range4, ONE);

		List<AddressRange> ranges = getMapRanges();
		assertEquals(4, ranges.size());
		assertEquals(range1, ranges.get(0));
		assertEquals(range2, ranges.get(1));
		assertEquals(range3, ranges.get(2));
		assertEquals(range4, ranges.get(3));
	}

	@Test
	public void testAddressIteratorWithStartAddressBeforeFirstRange() {
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x5));
		assertEquals(3, ranges.size());
		assertEquals(range2, ranges.get(0));
		assertEquals(range3, ranges.get(1));
		assertEquals(range4, ranges.get(2));

	}

	@Test
	public void testAddressIteratorWithStartAddressInFirstRange() {
		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x5));
		assertEquals(4, ranges.size());
		assertEquals(range(addr(0x5), range1.getMaxAddress()), ranges.get(0));
		assertEquals(range2, ranges.get(1));
		assertEquals(range3, ranges.get(2));
		assertEquals(range4, ranges.get(3));
	}

	@Test
	public void testAddressIteratorWithStartAddressBetweenFirstAndSecondRange() {
		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x15));
		assertEquals(3, ranges.size());
		assertEquals(range2, ranges.get(0));
		assertEquals(range3, ranges.get(1));
		assertEquals(range4, ranges.get(2));
	}

	@Test
	public void testAddressIteratorWithStartAddressInSecondRange() {
		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x25));
		assertEquals(3, ranges.size());
		assertEquals(range(addr(0x25), range2.getMaxAddress()), ranges.get(0));
		assertEquals(range3, ranges.get(1));
		assertEquals(range4, ranges.get(2));
	}

	@Test
	public void testAddressIteratorWithStartAddressInLastRange() {
		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), addr(0x1000));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x600));
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x600), range4.getMaxAddress()), ranges.get(0));
	}

	@Test
	public void testAddressIteratorWithStartAddressAfterLastRange() {
		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), addr(0x600));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating after last range
		List<AddressRange> ranges = getMapRanges(addr(0x1000));
		assertEquals(0, ranges.size());
	}

	@Test
	public void testAddressIteratorWithImageBaseStartAddressInFirstRange() {

		Address imageBase = addr(0x100);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(spaceMax.subtract(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x5));
		assertEquals(4, ranges.size());
		assertEquals(range(addr(0x5), range1.getMaxAddress()), ranges.get(0));
		assertEquals(range2, ranges.get(1));
		assertEquals(range3, ranges.get(2));
		assertEquals(range4, ranges.get(3));
	}

	@Test
	public void testAddressIteratorWithImageBaseStartAddressBetweenFirstAndSecondRange() {

		Address imageBase = addr(0x100);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x15));
		assertEquals(3, ranges.size());
		assertEquals(range2, ranges.get(0));
		assertEquals(range3, ranges.get(1));
		assertEquals(range4, ranges.get(2));
	}

	@Test
	public void testAddressIteratorWithImageBaseStartAddressInSecondRange() {

		Address imageBase = addr(0x100);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x25));
		assertEquals(3, ranges.size());
		assertEquals(range(addr(0x25), range2.getMaxAddress()), ranges.get(0));
		assertEquals(range3, ranges.get(1));
		assertEquals(range4, ranges.get(2));
	}

	@Test
	public void testAddressIteratorWithImageBaseStartAddressInLastRange() {

		Address imageBase = addr(0x100);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x10));
		AddressRange range2 = range(addr(0x20), addr(0x30));
		AddressRange range3 = range(addr(0x100), addr(0x200));
		AddressRange range4 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x600));
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x600), range4.getMaxAddress()), ranges.get(0));
	}

	@Test
	public void testGetAddressIteratorWithStartAndEndBeforeFirstRange() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x20), addr(0x50));
		assertEquals(0, ranges.size());
	}

	@Test
	public void testGetAddressIteratorWithStartAndEndBeforeInsideRange() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x310), addr(0x390));
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x310), addr(0x390)), ranges.get(0));
	}

	@Test
	public void testGetAddressIteratorWithStartInOneRangeEndInAnother() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x310), addr(0x610));
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x310), addr(0x400)), ranges.get(0));
		assertEquals(range(addr(0x600), addr(0x610)), ranges.get(1));
	}

	@Test
	public void testGetAddressIteratorWithStartAndEndPastLastRange() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x800), addr(0x900));
		assertEquals(0, ranges.size());
	}

	@Test
	public void testGetAddressIteratorWithImageBaseStartingAndEndingInSpanningRecord() {
		Address imageBase = addr(0x150);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x100));
		AddressRange range2 = range(addr(0x200), addr(0x300));
		AddressRange range3 = range(addr(0x500), addr(0x600));
		AddressRange range4 = range(addr(0x800), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), ONE);

		List<AddressRange> ranges = getMapRanges(addr(0x50), addr(0x1000));
		assertEquals(4, ranges.size());
		assertEquals(range(addr(0x50), range1.getMaxAddress()), ranges.get(0));
		assertEquals(range2, ranges.get(1));
		assertEquals(range3, ranges.get(2));
		assertEquals(range(range4.getMinAddress(), addr(0x1000)), ranges.get(3));
	}

	@Test
	public void testGetAddressIteratorWithImageBaseWithStartAndEndIncludeAll() {
		Address imageBase = addr(0x250);
		addrMap.setImageBase(imageBase);
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x150), addr(0x650));
		assertEquals(3, ranges.size());
		assertEquals(range(addr(0x150), range1.getMaxAddress()), ranges.get(0));
		assertEquals(range2, ranges.get(1));
		assertEquals(range(range3.getMinAddress(), addr(0x650)), ranges.get(2));
	}

	@Test
	public void testGetAddressIteratorWithImageBaseStartInOneRangeEndInAnother() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x600), addr(0x700));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		// try iterating starting in first range
		List<AddressRange> ranges = getMapRanges(addr(0x310), addr(0x610));
		assertEquals(2, ranges.size());
		assertEquals(range(addr(0x310), addr(0x400)), ranges.get(0));
		assertEquals(range(addr(0x600), addr(0x610)), ranges.get(1));
	}

	@Test
	public void testGetAddressSet() {
		map.paintRange(addr(0x100), addr(0x200), ONE);
		map.paintRange(addr(0x300), addr(0x400), TWO);

		AddressSet set = map.getAddressSet();
		assertEquals(2, set.getNumAddressRanges());
		assertEquals(range(addr(0x100), addr(0x200)), set.getFirstRange());
		assertEquals(range(addr(0x300), addr(0x400)), set.getLastRange());
	}

	@Test
	public void testGetAddressSetWithImageBaseSet() {
		addrMap.setImageBase(addr(0x100));
		map.paintRange(addr(0), spaceMax, ONE);
		AddressSet set = map.getAddressSet();
		assertEquals(1, set.getNumAddressRanges());
		assertEquals(range(addr(0), spaceMax), set.getFirstRange());
	}

	@Test
	public void testGetAddressRangeContaining() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), TWO);

		assertEquals(range1, map.getAddressRangeContaining(addr(0x100)));
		assertEquals(range1, map.getAddressRangeContaining(addr(0x150)));
		assertEquals(range1, map.getAddressRangeContaining(addr(0x200)));
		assertEquals(range2, map.getAddressRangeContaining(addr(0x300)));
		assertEquals(range2, map.getAddressRangeContaining(addr(0x350)));
		assertEquals(range2, map.getAddressRangeContaining(addr(0x400)));

		assertEquals(range(addr(0), addr(0xff)), map.getAddressRangeContaining(addr(0x0)));
		assertEquals(range(addr(0x201), addr(0x2ff)), map.getAddressRangeContaining(addr(0x250)));
		assertEquals(range(addr(0x401), spaceMax), map.getAddressRangeContaining(addr(0x900)));
	}

	@Test
	public void testGetRangeContainingWithStartKeyGreaterThanEndKey() {
		AddressRange range = range(addr(0), addr(0x200));
		AddressRange noValueRange = range(addr(0x201), spaceMax);
		addrMap.setImageBase(addr(0x100));
		// address 0 will have a high key, and address 0x200 will have a low key
		map.paintRange(range.getMinAddress(), range.getMaxAddress(), ONE);

		assertEquals(range, map.getAddressRangeContaining(addr(0)));
		assertEquals(range, map.getAddressRangeContaining(addr(0x100)));
		assertEquals(range, map.getAddressRangeContaining(addr(0x200)));

		assertEquals(noValueRange, map.getAddressRangeContaining(addr(0x201)));
		assertEquals(noValueRange, map.getAddressRangeContaining(addr(0x500)));
		assertEquals(noValueRange, map.getAddressRangeContaining(spaceMax));

	}

	@Test
	public void testGetRangeContainingWithWrappingAddressRecordAndStartKeyGreaterThanEndKey() {
		addrMap.setImageBase(addr(0x200));
		// address 0 will have a high key, and address 0x200 will have a low key
		map.paintRange(addr(0), addr(0x400), ONE);
		addrMap.setImageBase(addr(0x100));
		map.invalidate();

		AddressRange rangeLow = range(addr(0), addr(0x300));
		AddressRange rangeHigh = range(addr(0).subtractWrap(0x100), spaceMax);
		AddressRange noValueRange = range(addr(0x301), rangeHigh.getMinAddress().subtract(1));

		assertEquals(rangeLow, map.getAddressRangeContaining(addr(0)));
		assertEquals(rangeLow, map.getAddressRangeContaining(addr(0x100)));
		assertEquals(rangeLow, map.getAddressRangeContaining(addr(0x200)));
		assertEquals(rangeLow, map.getAddressRangeContaining(addr(0x300)));

		assertEquals(rangeHigh, map.getAddressRangeContaining(spaceMax));
		assertEquals(rangeHigh, map.getAddressRangeContaining(rangeHigh.getMinAddress()));

		assertEquals(noValueRange, map.getAddressRangeContaining(addr(0x301)));
		assertEquals(noValueRange, map.getAddressRangeContaining(addr(0x500)));
		assertEquals(noValueRange,
			map.getAddressRangeContaining(rangeHigh.getMinAddress().subtract(1)));

	}

	@Test
	public void testGetAddressRangeContainingWithSpanningAddressBoundary() {
		map.paintRange(addr(0), addr(0x200), ONE);

		// move the image base to make the above range partially wrap into upper address
		addrMap.setImageBase(addr(0).subtractWrap(0x100));

		// there is still currently only one record
		assertEquals(1, map.getRecordCount());

		List<AddressRange> ranges = getMapRanges();
		assertEquals(range(addr(0), addr(0x100)), ranges.get(0));
		assertEquals(range(addr(0).subtractWrap(0x100), spaceMax), ranges.get(1));
	}

	@Test
	public void testRangeWithImageBaseMoveToInsideRange() {
		map.paintRange(addr(0x10), addr(0x20), ONE);

		assertNull(map.getValue(addr(0)));
		assertEquals(ONE, map.getValue(addr(0x10)));
		assertEquals(ONE, map.getValue(addr(0x15)));
		assertEquals(ONE, map.getValue(addr(0x20)));
		assertNull(map.getValue(addr(0x25)));

		List<AddressRange> ranges = getMapRanges();
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0x10), addr(0x20)), ranges.get(0));

		Address imageBase = addr(0x15);
		addrMap.setImageBase(imageBase);
		// if the image base changes, the map has to be told so that it can clear its cache.
		map.invalidate();

		// now range should be from 0x25 to 0x35
		assertNull(map.getValue(addr(0)));
		assertNull(map.getValue(addr(0x10)));
		assertNull(map.getValue(addr(0x15)));
		assertNull(map.getValue(addr(0x20)));
		assertEquals(ONE, map.getValue(addr(0x25)));
		assertEquals(ONE, map.getValue(addr(0x30)));
		assertEquals(ONE, map.getValue(addr(0x35)));
		assertNull(map.getValue(addr(0x36)));

		ranges = getMapRanges();
		assertEquals(1, ranges.size());
		// image base will cause range to be two pieces, but effectively same set of addresses
		assertEquals(range(addr(0x25), addr(0x35)), ranges.get(0));

	}

	@Test
	public void testValueRangeSet() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x500), addr(0x600));
		AddressRange range4 = range(addr(0x700), addr(0x800));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), TWO);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), TWO);

		AddressSet setOne = addressSet(range1, range3);
		AddressSet setTwo = addressSet(range2, range4);

		assertEquals(setOne, map.getAddressSet(ONE));
		assertEquals(setTwo, map.getAddressSet(TWO));

	}

	@Test
	public void testValueRangeSetWithNoGaps() {
		AddressRange range1 = range(addr(0x100), addr(0x500));
		AddressRange range2 = range(addr(0x200), addr(0x300));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), TWO);

		AddressSet setOne = addressSet(range1).subtract(addressSet(range2));
		AddressSet setTwo = addressSet(range2);

		assertEquals(setOne, map.getAddressSet(ONE));
		assertEquals(setTwo, map.getAddressSet(TWO));

	}

	@Test
	public void testValueRangeSetWithImageBaseAndSpanningRecord() {
		Address imageBase = addr(0x150);
		addrMap.setImageBase(imageBase);

		AddressRange range1 = range(addr(0x0), addr(0x100));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x500), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), TWO);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);

		assertEquals(addressSet(range1, range3), map.getAddressSet(ONE));
		assertEquals(addressSet(range2), map.getAddressSet(TWO));
	}

	@Test
	public void testValueRangeSetWithValueNotInMap() {
		AddressRange range1 = range(addr(0x100), addr(0x500));
		AddressRange range2 = range(addr(0x200), addr(0x300));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), ONE);

		assertEquals(addressSet(), map.getAddressSet(TWO));
	}

	@Test
	public void testGetAddressSetForValue() {
		AddressRange range1 = range(addr(0x100), addr(0x200));
		AddressRange range2 = range(addr(0x300), addr(0x400));
		AddressRange range3 = range(addr(0x500), addr(0x600));
		AddressRange range4 = range(addr(0x700), addr(0x800));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), TWO);
		map.paintRange(range3.getMinAddress(), range3.getMaxAddress(), ONE);
		map.paintRange(range4.getMinAddress(), range4.getMaxAddress(), TWO);

		AddressSet addressSet = map.getAddressSet(ONE);
		assertEquals(2, addressSet.getNumAddressRanges());
		assertEquals(range1, addressSet.getFirstRange());
		assertEquals(range3, addressSet.getLastRange());

		addressSet = map.getAddressSet(TWO);
		assertEquals(2, addressSet.getNumAddressRanges());
		assertEquals(range2, addressSet.getFirstRange());
		assertEquals(range4, addressSet.getLastRange());
	}

	@Test
	public void testPaintAfterImageBaseChangeSplitsWrappingRecord() {
		AddressRange range1 = range(addr(0x00), addr(0x200));
		AddressRange range2 = range(addr(0x500), addr(0x600));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		assertEquals(1, map.getRecordCount());
		assertEquals(1, getMapRanges().size());
		assertEquals(range1, getMapRanges().get(0));

		Address imageBase = spaceMax.subtract(0xff);
		addrMap.setImageBase(imageBase);
		map.invalidate();

		assertEquals(1, map.getRecordCount());
		assertEquals(2, getMapRanges().size());
		assertEquals(range(addr(0), addr(0x100)), getMapRanges().get(0));
		assertEquals(range(imageBase, spaceMax), getMapRanges().get(1));

		// do another paint and see that the record got split
		// any paint will do, so do a paint that effectively does nothing
		map.paintRange(range2.getMinAddress(), range2.getMaxAddress(), null);
		assertEquals(2, map.getRecordCount());
		assertEquals(2, getMapRanges().size());
		assertEquals(range(imageBase, spaceMax), getMapRanges().get(0));
		assertEquals(range(addr(0), addr(0x100)), getMapRanges().get(1));

	}

	@Test
	public void testRangeIteratorWithRestrictionsSuchThatStartRangeIsOnlyRange() {
		AddressRange range1 = range(addr(0x00), addr(0x200));

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		assertEquals(1, map.getRecordCount());
		assertEquals(1, getMapRanges().size());
		assertEquals(range1, getMapRanges().get(0));

		Address imageBase = spaceMax.subtract(0xff);
		addrMap.setImageBase(imageBase);
		map.invalidate();

		List<AddressRange> ranges = getMapRanges(addr(0), addr(0x500));
		assertEquals(1, ranges.size());
		assertEquals(range(addr(0), addr(0x100)), ranges.get(0));

	}

	@Test
	public void testClearRangeThatEndsAtMaxAddress() {
		AddressRange range1 = range(spaceMax.subtract(0x100), spaceMax);

		map.paintRange(range1.getMinAddress(), range1.getMaxAddress(), ONE);
		assertEquals(1, map.getRecordCount());
		assertEquals(1, getMapRanges().size());
		assertEquals(range1, getMapRanges().get(0));

		map.clearRange(addr(0), spaceMax);
		List<AddressRange> ranges = getMapRanges();
		assertEquals(0, ranges.size());
	}

	private AddressRange range(Address start, Address end) {
		return new AddressRangeImpl(start, end);
	}

	private List<AddressRange> getMapRanges() {
		AddressRangeIterator addressRanges = map.getAddressRanges();
		List<AddressRange> ranges = new ArrayList<AddressRange>();
		for (AddressRange addressRange : addressRanges) {
			ranges.add(addressRange);
		}
		return ranges;
	}

	private List<AddressRange> getMapRanges(Address start) {
		AddressRangeIterator addressRanges = map.getAddressRanges(start);
		List<AddressRange> ranges = new ArrayList<AddressRange>();
		for (AddressRange addressRange : addressRanges) {
			ranges.add(addressRange);
		}
		return ranges;
	}

	private List<AddressRange> getMapRanges(Address start, Address end) {
		AddressRangeIterator addressRanges = map.getAddressRanges(start, end);
		List<AddressRange> ranges = new ArrayList<AddressRange>();
		for (AddressRange addressRange : addressRanges) {
			ranges.add(addressRange);
		}
		return ranges;
	}

	private void checkRange(AddressRange range, Field value) {
		checkRange(range, value, null, null);
	}

	private void checkRange(AddressRange range, Field value, Field valueBeforeRange,
			Field valueAfterRange) {
		Address start = range.getMinAddress();
		Address end = range.getMaxAddress();

		assertEquals("Value at range start " + range, value, map.getValue(start));
		assertEquals("Value at range end " + range, value, map.getValue(end));

		// if not at zero, check that value doesn't exist just before range;
		if (start.compareTo(addr(0)) > 0) {
			assertEquals("Value before range " + range, valueBeforeRange,
				map.getValue(start.subtract(1)));
		}

		// if not at end, check that value doesn't exist just past range
		if (end.compareTo(spaceMax) < 0) {
			assertEquals("Value after range " + range, valueAfterRange, map.getValue(end.add(1)));
		}
	}

	private AddressSet addressSet(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange range : ranges) {
			set.add(range);
		}
		return set;
	}
}
