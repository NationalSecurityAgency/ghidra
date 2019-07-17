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
/*
 * AddressObjectMapTest.java
 *
 * Created on January 7, 2002, 4:12 PM
 */

package ghidra.program.model.address;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.datastruct.NoSuchIndexException;
import ghidra.util.prop.ObjectPropertySet;

/**
 *
 * 
 * @version 
 */
public class AddressObjectMapTest extends AbstractGenericTest {
	AddressSpace space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);

	Address addr0 = new GenericAddress(space, 0);
	Address addr2 = new GenericAddress(space, 2);
	Address addr4 = new GenericAddress(space, 4);
	Address addr22 = new GenericAddress(space, 22);
	Address addr32 = new GenericAddress(space, 32);
	Address addr44 = new GenericAddress(space, 44);
	Address addr45 = new GenericAddress(space, 45);
	Address addr48 = new GenericAddress(space, 48);
	Address addr90 = new GenericAddress(space, 90);
	Address addr100 = new GenericAddress(space, 100);
	Address addr1000 = new GenericAddress(space, 1000);

	AddressSet set1 = new AddressSet();
	AddressSet set2 = new AddressSet();
	AddressSet set3 = new AddressSet();
	AddressSet set4 = new AddressSet();
	AddressSet set5 = new AddressSet();
	AddressSet set6 = new AddressSet();
	AddressSet set7 = new AddressSet();
	AddressSet set8 = new AddressSet();
	AddressSet set9 = new AddressSet();

	AddressObjectMap map = new AddressObjectMap();

	/** Creates new AddressObjectMapTest */
	public AddressObjectMapTest() {
		super();
	}

	@Before
	public void setUp() {
		set1.addRange(addr0, addr4);
		set2.addRange(addr22, addr44);
		set3.addRange(addr45, addr45);
		set4.addRange(addr4, addr32);
		set5.addRange(addr2, addr22);
		set6.addRange(addr45, addr48);
		set7.addRange(addr100, addr100);
		set8.addRange(addr90, addr1000);
	}

	@Test
    public void testAdd() {
		// test add one
		map.addObject("Set1", set1);
		assertEquals("Set1", map.getObjects(set1.getMinAddress())[0]);
		assertEquals("Set1", map.getObjects(set1.getMinAddress().add(2))[0]);
		assertEquals("Set1", map.getObjects(set1.getMaxAddress())[0]);
		assertEquals(0, map.getObjects(set1.getMinAddress().subtractWrap(1)).length);
		assertEquals(0, map.getObjects(set1.getMaxAddress().add(1)).length);

		// test add second
		map.addObject("Set2", set2);
		assertEquals("Set2", map.getObjects(set2.getMinAddress())[0]);
		assertEquals("Set2", map.getObjects(addr32)[0]);
		assertEquals("Set2", map.getObjects(set2.getMaxAddress())[0]);
		assertEquals(0, map.getObjects(set2.getMinAddress().subtractWrap(1)).length);
		assertEquals(0, map.getObjects(set2.getMaxAddress().add(1)).length);

		assertEquals("Set1", map.getObjects(set1.getMinAddress())[0]);
		assertEquals("Set1", map.getObjects(set1.getMinAddress().add(2))[0]);
		assertEquals("Set1", map.getObjects(set1.getMaxAddress())[0]);
		assertEquals(0, map.getObjects(set1.getMinAddress().subtractWrap(1)).length);
		assertEquals(0, map.getObjects(set1.getMaxAddress().add(1)).length);

		map.addObject("Set3", set3);
		assertEquals("Set3", map.getObjects(set3.getMinAddress())[0]);
		assertEquals("Set3", map.getObjects(set3.getMaxAddress())[0]);
		assertEquals("Set2", map.getObjects(set3.getMinAddress().subtractWrap(1))[0]);
		assertEquals(0, map.getObjects(set1.getMaxAddress().add(1)).length);
	}

	@Test
    public void testAddOverlapped() {
		map.addObject("Set1", set1);
		map.addObject("Set2", set2);
		map.addObject("Set3", set3);
		map.addObject("Set4", set4);
		assertEquals("Set1", map.getObjects(set4.getMinAddress())[0]);
		assertEquals("Set4", map.getObjects(set4.getMinAddress())[1]);
		assertEquals("Set2", map.getObjects(set4.getMaxAddress())[0]);
		assertEquals("Set4", map.getObjects(set4.getMaxAddress())[1]);
		assertEquals("Set2", map.getObjects(set4.getMaxAddress().add(2))[0]);
		assertEquals("Set1", map.getObjects(set4.getMinAddress().subtractWrap(1))[0]);
		assertEquals("Set2", map.getObjects(set4.getMaxAddress().add(1))[0]);

		map.addObject("Set5", set5);
		assertEquals("Set1", map.getObjects(addr2)[0]);
		assertEquals("Set5", map.getObjects(addr2)[1]);
		assertEquals("Set1", map.getObjects(addr4)[0]);
		assertEquals("Set4", map.getObjects(addr4)[1]);
		assertEquals("Set5", map.getObjects(addr4)[2]);
		assertEquals("Set4", map.getObjects(addr4.add(2))[0]);
		assertEquals("Set5", map.getObjects(addr4.add(2))[1]);
		assertEquals("Set2", map.getObjects(addr22)[0]);
		assertEquals("Set4", map.getObjects(addr22)[1]);
		assertEquals("Set5", map.getObjects(addr22)[2]);
		assertEquals("Set2", map.getObjects(addr22.add(2))[0]);
		assertEquals("Set4", map.getObjects(addr22.add(2))[1]);

		map.addObject("Set6", set6);
		assertEquals("Set3", map.getObjects(addr45)[0]);
		assertEquals("Set6", map.getObjects(addr45)[1]);
		assertEquals("Set6", map.getObjects(addr48)[0]);
		assertEquals("Set2", map.getObjects(addr44)[0]);
		assertEquals("Set6", map.getObjects(addr45.add(1))[0]);
		assertEquals(0, map.getObjects(addr48.add(1)).length);

		map.addObject("Set7", set7);
		map.addObject("Set7a", set7);
		assertEquals("Set7", map.getObjects(addr100)[0]);
		assertEquals("Set7a", map.getObjects(addr100)[1]);
		assertEquals(0, map.getObjects(addr100.add(1)).length);
		assertEquals(0, map.getObjects(addr100.subtractWrap(1)).length);

		map.addObject("Set8", set8);
		assertEquals("Set8", map.getObjects(addr90)[0]);
		assertEquals("Set8", map.getObjects(addr1000)[0]);
		assertEquals("Set7", map.getObjects(addr100)[0]);
		assertEquals("Set7a", map.getObjects(addr100)[1]);
		assertEquals("Set8", map.getObjects(addr100)[2]);

	}

	@Test
    public void testAddOverlapRangeRange() {
		testAddSets(10, 30, 20, 40);// range overlapping multi
		testAddSets(10, 40, 20, 30);// range containing range
		testAddSets(10, 20, 20, 30);// range overlapping one
		testAddSets(10, 10, 10, 10);// single single
		testAddSets(10, 30, 20, 20);// single bracketed
		testAddSets(10, 10, 10, 20);// single at begin of range
		testAddSets(10, 20, 20, 20);// single at end of range
		testAddSets(20, 20, 21, 21);// consecutive singles
		testAddSets(10, 20, 21, 30);// consecutive ranges
		testAddSets(10, 20, 30, 40);// disjoint ranges
		testAddSets(10, 10, 20, 20);// disjoint singles
		testAddSets(10, 20, 21, 21);// consecutive single at end
		testAddSets(20, 20, 21, 30);// consecutive single at begin
	}

	private void testAddSets(int aStart, int aEnd, int bStart, int bEnd) {
		Address startA = new GenericAddress(space, aStart);
		Address endA = new GenericAddress(space, aEnd);
		Address startB = new GenericAddress(space, bStart);
		Address endB = new GenericAddress(space, bEnd);

		AddressSet setA = new AddressSet();
		setA.addRange(startA, endA);
		AddressSet setB = new AddressSet();
		setB.addRange(startB, endB);

		testAddSets(setA, setB);
		testAddSets(setB, setA);
	}

	private void testAddSets(AddressSet setA, AddressSet setB) {
		AddressObjectMap testMap = new AddressObjectMap();

		testMap.addObject(setA, setA);
		testMap.addObject(setB, setB);

		testContains(testMap, setA);
		testContains(testMap, setB);
	}

	private void testContains(AddressObjectMap testMap, AddressSet set) {
		Address before = set.getMinAddress().subtractWrap(1);
		Address after = set.getMaxAddress().add(1);
		assertEquals(false, testContains(testMap, set, before));
		assertEquals(false, testContains(testMap, set, after));

		AddressIterator iter = set.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertEquals(true, testContains(testMap, set, addr));
		}
	}

	private void testNotContains(AddressObjectMap testMap, AddressSet set) {
		Address before = set.getMinAddress().subtractWrap(1);
		Address after = set.getMaxAddress().add(1);
		assertEquals(false, testContains(testMap, set, before));
		assertEquals(false, testContains(testMap, set, after));

		AddressIterator iter = set.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertEquals("addr = " + addr, false, testContains(testMap, set, addr));
		}
	}

	private boolean testContains(AddressObjectMap testMap, AddressSet set, Address addr) {
		Object objs[] = testMap.getObjects(addr);
		for (int i = 0; i < objs.length; i++) {
			if (objs[i].equals(set)) {
				return true;
			}
		}
		return false;
	}

	@Test
    public void testRemove() {

		testRemoveSets(10, 30, 20, 40);// range overlapping multi
		testRemoveSets(10, 40, 20, 30);// range containing range
		testRemoveSets(10, 20, 20, 30);// range overlapping one
		testRemoveSets(10, 10, 10, 10);// single single
		testRemoveSets(10, 30, 20, 20);// single bracketed
		testRemoveSets(10, 10, 10, 20);// single at begin of range
		testRemoveSets(10, 20, 20, 20);// single at end of range
		testRemoveSets(20, 20, 21, 21);// consecutive singles
		testRemoveSets(10, 20, 21, 30);// consecutive ranges
		testRemoveSets(10, 20, 30, 40);// disjoint ranges
		testRemoveSets(10, 10, 20, 20);// disjoint singles
		testRemoveSets(10, 20, 21, 21);// consecutive single at end
		testRemoveSets(20, 20, 21, 30);// consecutive single at begin
	}

	@Test
    public void testCoalesce() throws Exception {
		testAddCoalesce(10, 20, 21, 30);
		testAddCoalesce(21, 31, 10, 20);
		testAddCoalesce(10, 20, 21, 21);
		testAddCoalesce(21, 21, 10, 20);
		testAddCoalesce(10, 30, 20, 40);

		testRemoveCoalesce(10, 30, 20, 30);
		testRemoveCoalesce(10, 30, 20, 25);
		testRemoveCoalesce(10, 30, 10, 15);
		testRemoveCoalesce(10, 30, 5, 40);
		testRemoveCoalesce(10, 30, 20, 40);
		testRemoveCoalesce(10, 20, 30, 40);
	}

	private void testAddCoalesce(int aStart, int aEnd, int bStart, int bEnd) throws Exception {

		Address startA = new GenericAddress(space, aStart);
		Address endA = new GenericAddress(space, aEnd);
		Address startB = new GenericAddress(space, bStart);
		Address endB = new GenericAddress(space, bEnd);

		AddressSet setA = new AddressSet();
		setA.addRange(startA, endA);
		AddressSet setB = new AddressSet();
		setB.addRange(startB, endB);

		AddressObjectMap testMap = new AddressObjectMap();
		testMap.addObject("one", setA);
		testMap.addObject("one", setB);

		AddressMapImpl addrMap = (AddressMapImpl) getInstanceField("addrMap", testMap);
		ObjectPropertySet objMarkers = (ObjectPropertySet) getInstanceField("objMarkers", testMap);

		long start = Math.min(addrMap.getKey(startA), addrMap.getKey(startB));
		long end = Math.max(addrMap.getKey(endA), addrMap.getKey(endB));

		long firstMark = objMarkers.getFirstPropertyIndex();
		long lastMark = objMarkers.getLastPropertyIndex();
		assertEquals(start, firstMark);
		assertEquals(end, lastMark);
		assertEquals(lastMark, objMarkers.getNextPropertyIndex(firstMark));
	}

	private void testRemoveCoalesce(int aStart, int aEnd, int bStart, int bEnd) {
		Address startA = new GenericAddress(space, aStart);
		Address endA = new GenericAddress(space, aEnd);
		Address startB = new GenericAddress(space, bStart);
		Address endB = new GenericAddress(space, bEnd);

		AddressSet setA = new AddressSet();
		setA.addRange(startA, endA);
		AddressSet setB = new AddressSet();
		setB.addRange(startB, endB);

		AddressObjectMap testMap = new AddressObjectMap();
		testMap.addObject("one", setA);
		testMap.addObject("two", setB);
		testMap.removeObject("two", setB);

		AddressMapImpl addrMap = (AddressMapImpl) getInstanceField("addrMap", testMap);
		ObjectPropertySet objMarkers = (ObjectPropertySet) getInstanceField("objMarkers", testMap);

		try {
			long firstMark = objMarkers.getFirstPropertyIndex();
			long lastMark = objMarkers.getLastPropertyIndex();
			assertEquals(addrMap.getKey(startA), firstMark);
			assertEquals(addrMap.getKey(endA), lastMark);
			assertEquals(lastMark, objMarkers.getNextPropertyIndex(firstMark));
		}
		catch (NoSuchIndexException e) {
			Assert.fail();
		}
	}

	private void testRemoveSets(int aStart, int aEnd, int bStart, int bEnd) {
		Address startA = new GenericAddress(space, aStart);
		Address endA = new GenericAddress(space, aEnd);
		Address startB = new GenericAddress(space, bStart);
		Address endB = new GenericAddress(space, bEnd);

		AddressSet setA = new AddressSet();
		setA.addRange(startA, endA);
		AddressSet setB = new AddressSet();
		setB.addRange(startB, endB);

		testRemoveSets(setA, setB);
		testRemoveSets(setB, setA);
	}

	private void testRemoveSets(AddressSet setA, AddressSet setB) {

		AddressObjectMap testMap = new AddressObjectMap();

		testMap.addObject(setA, setA);
		testMap.addObject(set2, set2);

		testMap.removeObject(setA, setA);
		testNotContains(testMap, setA);
		if (setA.equals(set2)) {// if same sets, set2 is gone now too
			testNotContains(testMap, set2);
		}
		else
			testContains(testMap, set2);
	}
}
