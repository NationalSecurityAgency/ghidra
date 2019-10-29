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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockStub;

public class ByteSourceRangeTest extends AbstractGenericTest {
	private AddressSpace space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);
	private MemoryBlock block = new MemoryBlockStub();
	@Test
	public void testIntersectNotSameSource() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x10, 2, 0x50);
		assertNull(range1.intersect(range2));
	}

	@Test
	public void testIntersectOneRangeSimpleOverlap() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x20, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x20, 1, 0x60);

		ByteSourceRange intersect = range1.intersect(range2);
		assertNotNull(intersect);
		assertEquals(addr(0x10), intersect.getStart());
		assertEquals(addr(0x1f), intersect.getEnd());
		assertEquals(0x10, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x60, intersect.getOffset());

		intersect = range2.intersect(range1);
		assertNotNull(intersect);
		assertEquals(addr(0x100), intersect.getStart());
		assertEquals(addr(0x10f), intersect.getEnd());
		assertEquals(0x10, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x60, intersect.getOffset());
	}

	@Test
	public void testIntersectOneRangeButsAgainsAnother() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x20, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x20, 2, 0x70);

		assertNull(range1.intersect(range2));
		assertNull(range2.intersect(range1));
	}


	@Test
	public void testIntersectOneRangeCompletelyInAnother() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x30, 1, 0x40);
		
		ByteSourceRange intersect = range1.intersect(range2);
		assertNotNull(intersect);
		assertEquals(addr(0), intersect.getStart());
		assertEquals(addr(0xf), intersect.getEnd());
		assertEquals(0x10, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x50, intersect.getOffset());

		intersect = range2.intersect(range1);
		assertNotNull(intersect);
		assertEquals(addr(0x110), intersect.getStart());
		assertEquals(addr(0x11f), intersect.getEnd());
		assertEquals(0x10, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x50, intersect.getOffset());
	}

	@Test
	public void testBitMappedIntersect() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRange range2 = new BitMappedByteSourceRange(block, addr(0x100), 1, 0x55, 2);

		ByteSourceRange intersect = range1.intersect(range2);
		assertNotNull(intersect);
		assertEquals(addr(5), intersect.getStart());
		assertEquals(addr(6), intersect.getEnd());
		assertEquals(2, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x55, intersect.getOffset());

		intersect = range2.intersect(range1);
		assertNotNull(intersect);
		assertEquals(addr(0x100), intersect.getStart());
		assertEquals(addr(0x10f), intersect.getEnd());
		assertEquals(2, intersect.getSize());
		assertEquals(1, intersect.getSourceId());
		assertEquals(0x55, intersect.getOffset());
		
	}

	private Address addr(long value) {
		return space.getAddress(value);
	}

}

