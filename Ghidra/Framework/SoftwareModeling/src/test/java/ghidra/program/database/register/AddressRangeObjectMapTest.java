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
package ghidra.program.database.register;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

public class AddressRangeObjectMapTest extends AbstractGenericTest {

	private GenericAddressSpace space;

	public AddressRangeObjectMapTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		space = new GenericAddressSpace("Test", 32, AddressSpace.TYPE_RAM, 0);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

@Test
    public void testTwoSpacesWithSecondRangeAt0() throws Exception {
		AddressSpace space2 = new GenericAddressSpace("Test2", 32, AddressSpace.TYPE_RAM, 1);
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();
		Integer one = new Integer(1);
		rangeMap.setObject(addr(0x1000), addr(0x2000), one);
		rangeMap.setObject(space2.getAddress(0), space2.getAddress(10), one);
		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		Assert.assertEquals(addr(0x1000), range.getMinAddress());
		Assert.assertEquals(addr(0x2000), range.getMaxAddress());

		assertTrue(it.hasNext());
		range = it.next();
		Assert.assertEquals(space2.getAddress(0), range.getMinAddress());
		Assert.assertEquals(space2.getAddress(10), range.getMaxAddress());

		assertTrue(!it.hasNext());

	}

@Test
    public void testAddOverlappingRangeWithSameObject() {
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();

		Integer one = new Integer(1);

		rangeMap.setObject(addr(0x1000), addr(0x2000), one);
		rangeMap.setObject(addr(0x1500), addr(0x3000), one);

		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		Assert.assertEquals(addr(0x1000), range.getMinAddress());
		Assert.assertEquals(addr(0x3000), range.getMaxAddress());
		Assert.assertEquals(one, rangeMap.getObject(addr(0x1000)));
		assertTrue(!it.hasNext());

	}

@Test
    public void testAddAdjoiningRangesWithSameObject() {
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();

		Integer one = new Integer(1);

		rangeMap.setObject(addr(0x1000), addr(0x2000), one);
		rangeMap.setObject(addr(0x2001), addr(0x3000), one);

		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		Assert.assertEquals(addr(0x1000), range.getMinAddress());
		Assert.assertEquals(addr(0x3000), range.getMaxAddress());
		Assert.assertEquals(one, rangeMap.getObject(addr(0x1000)));
		assertTrue(!it.hasNext());

	}

	@Test
	public void testAddAdjoiningRangesWithDifferentObject() {
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();

		Integer one = new Integer(1);
		Integer two = new Integer(2);

		rangeMap.setObject(addr(0x1000), addr(0x2000), one);
		rangeMap.setObject(addr(0x2001), addr(0x3000), two);

		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		assertEquals(addr(0x1000), range.getMinAddress());
		assertEquals(addr(0x2000), range.getMaxAddress());
		assertTrue(it.hasNext());
		range = it.next();
		assertEquals(addr(0x2001), range.getMinAddress());
		assertEquals(addr(0x3000), range.getMaxAddress());
		assertEquals(one, rangeMap.getObject(addr(0x1000)));
		assertEquals(two, rangeMap.getObject(addr(0x2001)));
		assertTrue(!it.hasNext());

	}

	public void testAddCompletelyCoveredRangeWithDifferentObject() {
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();

		Integer one = new Integer(1);
		Integer two = new Integer(2);

		rangeMap.setObject(addr(0x1000), addr(0x2000), one);
		rangeMap.setObject(addr(0x500), addr(0x3000), two);

		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		Assert.assertEquals(addr(0x500), range.getMinAddress());
		Assert.assertEquals(addr(0x3000), range.getMaxAddress());
		Assert.assertEquals(two, rangeMap.getObject(addr(0x1000)));
		assertTrue(!it.hasNext());
	}

@Test
    public void testAddSingleAddressRangeInMiddleOfExistingRangeWithDifferentObject() {
		AddressRangeObjectMap<Integer> rangeMap = new AddressRangeObjectMap<Integer>();

		Integer one = new Integer(1);
		Integer two = new Integer(2);

		rangeMap.setObject(addr(0x1000), addr(0x2000), one);

		AddressRangeIterator it = rangeMap.getAddressRangeIterator();
		assertTrue(it.hasNext());
		AddressRange range = it.next();
		Assert.assertEquals(addr(0x1000), range.getMinAddress());
		Assert.assertEquals(addr(0x2000), range.getMaxAddress());
		Assert.assertEquals(one, rangeMap.getObject(addr(0x1000)));
		assertTrue(!it.hasNext());

		rangeMap.setObject(addr(0x1500), addr(0x1500), two);
		it = rangeMap.getAddressRangeIterator();

		assertTrue(it.hasNext());
		range = it.next();
		Assert.assertEquals(addr(0x1000), range.getMinAddress());
		Assert.assertEquals(addr(0x14ff), range.getMaxAddress());
		Assert.assertEquals(one, rangeMap.getObject(addr(0x1000)));

		assertTrue(it.hasNext());
		range = it.next();
		Assert.assertEquals(addr(0x1500), range.getMinAddress());
		Assert.assertEquals(addr(0x1500), range.getMaxAddress());
		Assert.assertEquals(two, rangeMap.getObject(addr(0x1500)));

		assertTrue(it.hasNext());
		range = it.next();
		Assert.assertEquals(addr(0x1501), range.getMinAddress());
		Assert.assertEquals(addr(0x2000), range.getMaxAddress());
		Assert.assertEquals(one, rangeMap.getObject(addr(0x1501)));

		assertTrue(!it.hasNext());

	}
}
