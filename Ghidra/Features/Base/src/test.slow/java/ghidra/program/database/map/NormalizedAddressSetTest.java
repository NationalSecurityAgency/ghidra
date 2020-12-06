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

import java.util.Iterator;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class NormalizedAddressSetTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressMap addrMap;
	AddressFactory addressFactory;
	private AddressSpace sp;
	private NormalizedAddressSet set;

	public NormalizedAddressSetTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._SPARC64, this);
		addressFactory = program.getAddressFactory();

		MemoryMapDB memory = (MemoryMapDB) program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memory);
		sp = program.getAddressFactory().getDefaultAddressSpace();

		set = new NormalizedAddressSet(addrMap);

		program.startTransaction("TEST");
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
		addrMap = null;
	}

	private Address addr(long v) {
		return sp.getAddress(v);
	}

	@Test
	public void testAdd() {
		set.addRange(addr(0), addr(10));
		AddressSet addrSet = set.intersect(new AddressSet(addr(5), addr(15)));
		assertEquals(6, addrSet.getNumAddresses());
		assertEquals(addr(5), addrSet.getMinAddress());
		assertEquals(addr(10), addrSet.getMaxAddress());
	}

	@Test
	public void testAddBig() {
		set.addRange(addr(0xfffffff0l), addr(0xffffffffl));
		assertEquals(addr(0xfffffff0l), set.getMinAddress());
		assertEquals(addr(0xffffffffl), set.getMaxAddress());
	}

	@Test
	public void testUnionNonOverlap() {
		set.addRange(addr(0), addr(0));
		set.addRange(addr(5), addr(5));
		set.addRange(addr(0xffffffffL), addr(0xffffffffL));
		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		otherSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		otherSet.addRange(addr(40), addr(45));
		AddressSet uSet = set.union(otherSet);
		Iterator<AddressRange> it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(0)), it.next());
		assertEquals(new AddressRangeImpl(addr(5), addr(5)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(45)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffffL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(128, uSet.getNumAddresses());
		assertEquals(addr(0), uSet.getMinAddress());
		assertEquals(addr(0xffffffffL), uSet.getMaxAddress());
	}

	@Test
	public void testUnionWithOverlap() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffbbL), addr(0xfffffff0L));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));
		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		otherSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		otherSet.addRange(addr(40), addr(45));
		AddressSet uSet = set.union(otherSet);
		Iterator<AddressRange> it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(22)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(75)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffbbL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(229, uSet.getNumAddresses());
		assertEquals(addr(0), uSet.getMinAddress());
		assertEquals(addr(0xffffffffL), uSet.getMaxAddress());
	}

	@Test
	public void testUnionPosFirst() {
		set.addRange(addr(0), addr(0));
		set.addRange(addr(5), addr(5));
		set.addRange(addr(40), addr(45));
		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		otherSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		otherSet.addRange(addr(0xffffffffL), addr(0xffffffffL));
		AddressSet uSet = set.union(otherSet);
		Iterator<AddressRange> it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(0)), it.next());
		assertEquals(new AddressRangeImpl(addr(5), addr(5)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(45)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffffL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(128, uSet.getNumAddresses());
		assertEquals(addr(0), uSet.getMinAddress());
		assertEquals(addr(0xffffffffL), uSet.getMaxAddress());
	}

	@Test
	public void testUnionNegFirst() {
		set.addRange(addr(0xffffffffL), addr(0xffffffffL));
		set.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		set.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		Iterator<AddressRange> it = set.iterator();
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffffL), addr(0xffffffffL)), it.next());

		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0), addr(0));
		otherSet.addRange(addr(5), addr(5));
		otherSet.addRange(addr(40), addr(45));
		it = otherSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(0)), it.next());
		assertEquals(new AddressRangeImpl(addr(5), addr(5)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(45)), it.next());

		AddressSet uSet = set.union(otherSet);
		it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(0)), it.next());
		assertEquals(new AddressRangeImpl(addr(5), addr(5)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(45)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffffL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(128, uSet.getNumAddresses());
		assertEquals(addr(0), uSet.getMinAddress());
		assertEquals(addr(0xffffffffL), uSet.getMaxAddress());
	}

	@Test
	public void testIntersectNonOverlap() {
		set.addRange(addr(0), addr(0));
		set.addRange(addr(5), addr(5));
		set.addRange(addr(0xffffffffL), addr(0xffffffffL));
		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		otherSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		otherSet.addRange(addr(40), addr(45));

		assertEquals(false, set.intersects(otherSet));
		AddressSet uSet = set.intersect(otherSet);
		assertEquals(0, uSet.getNumAddresses());

		assertEquals(false, otherSet.intersects(set));
		uSet = otherSet.intersect(set);
		assertEquals(0, uSet.getNumAddresses());
	}

	@Test
	public void testIntersectWithOverlap() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffbbL), addr(0xfffffff0L));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));
		AddressSet otherSet = new AddressSet();
		otherSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		otherSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		otherSet.addRange(addr(40), addr(45));

		assertEquals(true, set.intersects(otherSet));
		AddressSet uSet = set.intersect(otherSet);
		Iterator<AddressRange> it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(42), addr(45)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe10L), addr(0xfffffe20L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(39, uSet.getNumAddresses());
		assertEquals(addr(42), uSet.getMinAddress());
		assertEquals(addr(0xfffffffdL), uSet.getMaxAddress());

		assertEquals(true, otherSet.intersects(set));
		uSet = otherSet.intersect(set);
		it = uSet.iterator();
		assertEquals(new AddressRangeImpl(addr(42), addr(45)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe10L), addr(0xfffffe20L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffecL), addr(0xfffffffdL)), it.next());
		assertTrue(!it.hasNext());
		assertEquals(39, uSet.getNumAddresses());
		assertEquals(addr(42), uSet.getMinAddress());
		assertEquals(addr(0xfffffffdL), uSet.getMaxAddress());
	}

	@Test
	public void testDelete() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffbbL), addr(0xfffffff0L));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		NormalizedAddressSet deleteSet = new NormalizedAddressSet(addrMap);
		deleteSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		deleteSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		deleteSet.addRange(addr(40), addr(45));

		set.delete(deleteSet);
		Iterator<AddressRange> it = set.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(22)), it.next());
		assertEquals(new AddressRangeImpl(addr(46), addr(75)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffbbL), addr(0xffffffebL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffffeL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testSubtract() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffbbL), addr(0xfffffff0L));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		NormalizedAddressSet subtractSet = new NormalizedAddressSet(addrMap);
		subtractSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		subtractSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		subtractSet.addRange(addr(40), addr(45));

		AddressSet reducedSet = set.subtract(subtractSet);
		Iterator<AddressRange> it = reducedSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(22)), it.next());
		assertEquals(new AddressRangeImpl(addr(46), addr(75)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffbbL), addr(0xffffffebL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffffeL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testXor() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffbbL), addr(0xfffffff0L));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		NormalizedAddressSet subtractSet = new NormalizedAddressSet(addrMap);
		subtractSet.addRange(addr(0xfffffe0cL), addr(0xfffffe70L));
		subtractSet.addRange(addr(0xffffffecL), addr(0xfffffffdL));
		subtractSet.addRange(addr(40), addr(45));

		AddressSet xorSet = set.xor(subtractSet);
		Iterator<AddressRange> it = xorSet.iterator();
		assertEquals(new AddressRangeImpl(addr(0), addr(22)), it.next());
		assertEquals(new AddressRangeImpl(addr(40), addr(41)), it.next());
		assertEquals(new AddressRangeImpl(addr(46), addr(75)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe0cL), addr(0xfffffe0fL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffe21L), addr(0xfffffe70L)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xffffffbbL), addr(0xffffffebL)), it.next());
		assertEquals(new AddressRangeImpl(addr(0xfffffffeL), addr(0xffffffffL)), it.next());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testContains() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffb9L), addr(0xffffffbbL));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		assertEquals(true, set.contains(addr(0)));
		assertEquals(true, set.contains(addr(11)));
		assertEquals(true, set.contains(addr(22)));
		assertEquals(true, set.contains(addr(42)));
		assertEquals(true, set.contains(addr(52)));
		assertEquals(true, set.contains(addr(75)));
		assertEquals(true, set.contains(addr(0xfffffe10L)));
		assertEquals(true, set.contains(addr(0xfffffe18L)));
		assertEquals(true, set.contains(addr(0xfffffe20L)));
		assertEquals(true, set.contains(addr(0xffffffbbL)));
		assertEquals(true, set.contains(addr(0xffffffbaL)));
		assertEquals(true, set.contains(addr(0xffffffb9L)));
		assertEquals(true, set.contains(addr(0xffffffccL)));
		assertEquals(true, set.contains(addr(0xffffffd5L)));
		assertEquals(true, set.contains(addr(0xffffffffL)));
		assertEquals(false, set.contains(addr(23)));
		assertEquals(false, set.contains(addr(32)));
		assertEquals(false, set.contains(addr(41)));
		assertEquals(false, set.contains(addr(23)));
		assertEquals(false, set.contains(addr(76)));
		assertEquals(false, set.contains(addr(100)));
		assertEquals(false, set.contains(addr(0x80000000L)));
		assertEquals(false, set.contains(addr(0xfffffe0fL)));
		assertEquals(false, set.contains(addr(0xfffffe0fL)));
		assertEquals(false, set.contains(addr(0xfffffe21L)));
		assertEquals(false, set.contains(addr(0xfffffeffL)));
		assertEquals(false, set.contains(addr(0xffffffb8L)));
		assertEquals(false, set.contains(addr(0xffffffbcL)));
		assertEquals(false, set.contains(addr(0xffffffbfL)));
		assertEquals(false, set.contains(addr(0xffffffcbL)));
	}

	@Test
	public void testContains2() {
		set.addRange(addr(0), addr(0xffffffffL));

		assertEquals(true, set.contains(addr(0)));
		assertEquals(true, set.contains(addr(11)));
		assertEquals(true, set.contains(addr(22)));
		assertEquals(true, set.contains(addr(42)));
		assertEquals(true, set.contains(addr(52)));
		assertEquals(true, set.contains(addr(75)));
		assertEquals(true, set.contains(addr(0xfffffe10L)));
		assertEquals(true, set.contains(addr(0xfffffe18L)));
		assertEquals(true, set.contains(addr(0xfffffe20L)));
		assertEquals(true, set.contains(addr(0xffffffbbL)));
		assertEquals(true, set.contains(addr(0xffffffbaL)));
		assertEquals(true, set.contains(addr(0xffffffb9L)));
		assertEquals(true, set.contains(addr(0xffffffccL)));
		assertEquals(true, set.contains(addr(0xffffffd5L)));
		assertEquals(true, set.contains(addr(0xffffffffL)));
		assertEquals(true, set.contains(addr(23)));
		assertEquals(true, set.contains(addr(32)));
		assertEquals(true, set.contains(addr(41)));
		assertEquals(true, set.contains(addr(23)));
		assertEquals(true, set.contains(addr(76)));
		assertEquals(true, set.contains(addr(100)));
		assertEquals(true, set.contains(addr(0x80000000L)));
		assertEquals(true, set.contains(addr(0xfffffe0fL)));
		assertEquals(true, set.contains(addr(0xfffffe0fL)));
		assertEquals(true, set.contains(addr(0xfffffe21L)));
		assertEquals(true, set.contains(addr(0xfffffeffL)));
		assertEquals(true, set.contains(addr(0xffffffb8L)));
		assertEquals(true, set.contains(addr(0xffffffbcL)));
		assertEquals(true, set.contains(addr(0xffffffbfL)));
		assertEquals(true, set.contains(addr(0xffffffcbL)));
	}

	@Test
	public void testForwardIterator() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffb9L), addr(0xffffffbbL));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		Address checkAddress = addr(0);
		AddressIterator iter = set.getAddresses(true);
		while (iter.hasNext()) {
			Address addr = iter.next();
			assertEquals(checkAddress, addr);
			if (checkAddress.equals(addr(22))) {
				checkAddress = addr(42);
			}
			else if (checkAddress.equals(addr(75))) {
				checkAddress = addr(0xfffffe10L);
			}
			else if (checkAddress.equals(addr(0xfffffe20L))) {
				checkAddress = addr(0xffffffb9L);
			}
			else if (checkAddress.equals(addr(0xffffffbbL))) {
				checkAddress = addr(0xffffffccL);
			}
			else if (checkAddress.equals(addr(0xffffffffL))) {
				checkAddress = addr(0);
			}
			else {
				checkAddress = checkAddress.add(1L);
			}
		}
	}

	@Test
	public void testBackwardIterator() {
		set.addRange(addr(0), addr(22));
		set.addRange(addr(42), addr(75));
		set.addRange(addr(0xfffffe10L), addr(0xfffffe20L));
		set.addRange(addr(0xffffffb9L), addr(0xffffffbbL));
		set.addRange(addr(0xffffffccL), addr(0xffffffffL));

		Address checkAddress = addr(0xffffffffL);
		AddressIterator iter = set.getAddresses(false);
		while (iter.hasNext()) {
			Address addr = iter.next();

			assertEquals(checkAddress, addr);
			if (checkAddress.equals(addr(0xffffffccL))) {
				checkAddress = addr(0xffffffbbL);
			}
			else if (checkAddress.equals(addr(0xffffffb9L))) {
				checkAddress = addr(0xfffffe20L);
			}
			else if (checkAddress.equals(addr(0xfffffe10L))) {
				checkAddress = addr(75);
			}
			else if (checkAddress.equals(addr(42))) {
				checkAddress = addr(22);
			}
			else if (checkAddress.equals(addr(0))) {
				checkAddress = addr(0xffffffffL);
			}
			else {
				checkAddress = checkAddress.subtract(1L);
			}
		}
	}

}
