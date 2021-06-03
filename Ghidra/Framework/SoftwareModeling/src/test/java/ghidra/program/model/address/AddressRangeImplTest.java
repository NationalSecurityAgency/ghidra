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
package ghidra.program.model.address;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class AddressRangeImplTest extends AbstractGenericTest {
	private AddressSpace space;

	/**
	 * Constructor for AddressRangeImplTest.
	 * @param name
	 */
	public AddressRangeImplTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		space = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);
	}

	@Test
	public void testIntersect() {
		AddressRange r2 = new AddressRangeImpl(addr(0), addr(30));
		AddressRange r1 = new AddressRangeImpl(addr(5), addr(20));
		AddressRange r3 = r1.intersect(r2);
		assertNotNull(r3);
		Assert.assertEquals(addr(5), r3.getMinAddress());
		Assert.assertEquals(addr(20), r3.getMaxAddress());

		r1 = new AddressRangeImpl(addr(0), addr(30));
		r1 = new AddressRangeImpl(addr(40), addr(50));
		r3 = r1.intersect(r2);
		assertNull(r3);

		r1 = new AddressRangeImpl(addr(0), addr(30));
		r1 = new AddressRangeImpl(addr(30), addr(50));
		r3 = r1.intersect(r2);
		assertNotNull(r3);
		Assert.assertEquals(addr(30), r3.getMinAddress());
		Assert.assertEquals(addr(30), r3.getMaxAddress());

	}

	@Test
	public void testAddressRangeChunker_SameStartAndEndAddress() {
		Address start = addr(0);
		Address end = addr(0);

		AddressRangeImpl range = new AddressRangeImpl(start, end);
		AddressRangeChunker chunker = new AddressRangeChunker(range, 10);
		Iterator<AddressRange> it = chunker.iterator();
		assertTrue(it.hasNext());
		AddressRange r = it.next();
		Assert.assertEquals(addr(0), r.getMinAddress());
		Assert.assertEquals(addr(0), r.getMaxAddress());

		assertFalse(it.hasNext());
	}

	@Test
	public void testAddressRangeChunker_AddressRangeConstructor() {
		Address start = addr(0);
		Address end = addr(2);

		AddressRangeImpl range = new AddressRangeImpl(start, end);
		AddressRangeChunker chunker = new AddressRangeChunker(range, 1);
		Iterator<AddressRange> it = chunker.iterator();
		assertTrue(it.hasNext());
		AddressRange r = it.next();
		Assert.assertEquals(addr(0), r.getMinAddress());
		Assert.assertEquals(addr(0), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(1), r.getMinAddress());
		Assert.assertEquals(addr(1), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(2), r.getMinAddress());
		Assert.assertEquals(addr(2), r.getMaxAddress());

		assertFalse(it.hasNext());
	}

	@Test
	public void testAddressRangeChunker_LastRangeSmallerThanChunkSize() {
		Address start = addr(0);
		Address end = addr(30);

		AddressRangeChunker chunker = new AddressRangeChunker(start, end, 10);
		Iterator<AddressRange> it = chunker.iterator();
		assertTrue(it.hasNext());
		AddressRange r = it.next();
		Assert.assertEquals(addr(0), r.getMinAddress());
		Assert.assertEquals(addr(9), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(10), r.getMinAddress());
		Assert.assertEquals(addr(19), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(20), r.getMinAddress());
		Assert.assertEquals(addr(29), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(30), r.getMinAddress());

		assertFalse(it.hasNext());
	}

	@Test
	public void testAddressRangeChunker_LastRangeEqualToChunkSize() {
		Address start = addr(0);
		Address end = addr(29);

		AddressRangeChunker chunker = new AddressRangeChunker(start, end, 10);
		Iterator<AddressRange> it = chunker.iterator();
		assertTrue(it.hasNext());
		AddressRange r = it.next();
		Assert.assertEquals(addr(0), r.getMinAddress());
		Assert.assertEquals(addr(9), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(10), r.getMinAddress());
		Assert.assertEquals(addr(19), r.getMaxAddress());

		assertTrue(it.hasNext());
		r = it.next();
		Assert.assertEquals(addr(20), r.getMinAddress());
		Assert.assertEquals(addr(29), r.getMaxAddress());

		assertFalse(it.hasNext());
	}

	@Test
	public void testAddressRangeChunker_NullAddresses() {
		try {
			new AddressRangeChunker(null, addr(0), 10);
			Assert.fail("Did not get exception when passing null address to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}

		try {
			new AddressRangeChunker(addr(0), null, 10);
			Assert.fail("Did not get exception when passing null address to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}
	}

	@Test
	public void testAddressRangeChunker_BadChunkSize() {
		try {
			new AddressRangeChunker(addr(0), addr(1), -1);
			Assert.fail("Did not get exception when passing bad chunk size to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}

		try {
			new AddressRangeChunker(addr(0), addr(1), 0);
			Assert.fail("Did not get exception when passing bad chunk size to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}
	}

	@Test
	public void testAddressRangeChunker_StartLessThanEnd() {
		try {
			new AddressRangeChunker(addr(1), addr(0), 10);
			Assert.fail("Did not get exception when passing start less than end to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}

		new AddressRangeChunker(addr(0), addr(0), 10); // this is OK
	}

	@Test
	public void testAddressRangeChunker_DifferentAddressSpaces() {
		AddressSpace space1 = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);
		AddressSpace space2 = new GenericAddressSpace("yy", 32, AddressSpace.TYPE_RAM, 0);

		GenericAddress a1 = new GenericAddress(space1, 1);
		GenericAddress a2 = new GenericAddress(space2, 2);

		try {
			new AddressRangeChunker(a1, a2, 10);
			Assert.fail("Did not get exception when passing addresses from different address "
					+ "spaces to chunker.");
		}
		catch (IllegalArgumentException e) {
			// good!
		}
	}

	@Test
	public void testAddressRange_BoundsOrdering() {

		int size = 15;
		Address start = addr(5);
		Address limit = start.add(size);

		AddressRange r1 = new AddressRangeImpl(start, limit);
		assertTrue(r1.getMinAddress().compareTo(r1.getMaxAddress()) < 0);

		AddressRange r2 = new AddressRangeImpl(limit, start);
		assertTrue(r2.getMinAddress().compareTo(r2.getMaxAddress()) < 0);

		assertTrue(r1.compareTo(r2) == 0);
	}

	@Test
	public void testAddressRangeIteration_RangeEnumeration() {
		int size = 15;
		Address start = addr(5);
		Address limit = start.add(size);

		AddressRange r1 = new AddressRangeImpl(start, limit);
		int addrCount = 0;
		Iterator<Address> addrItr = r1.iterator();
		while (addrItr.hasNext()) {
			addrItr.next();
			addrCount++;
		}

		assertTrue(
			"Address Iterator does not properly enumerate address range: " +
					String.format("%s (%d long) -- found %d", r1.toString(), r1.getLength(), addrCount),
					addrCount == (size + 1));
	}

	@Test
	public void testAddressRangeIteration_Extent() {
		int size = 15;
		Address start = addr(5);
		Address limit = start.add(size);

		AddressRange r1 = new AddressRangeImpl(start, limit);

		Iterator<Address> addrItr = r1.iterator();
		Address lastAddr = Address.NO_ADDRESS;
		while (addrItr.hasNext()) {
			lastAddr = addrItr.next();
		}

		assertTrue("Address Iterator extent does not match end of range", lastAddr.equals(limit));
	}

	private Address addr(int a) {
		return new GenericAddress(space, a);
	}

}
