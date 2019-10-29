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

import java.util.Iterator;
import java.util.Set;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockStub;

public class ByteSourceRangeListTest extends AbstractGenericTest {
	private AddressSpace space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);
	private MemoryBlock block = new MemoryBlockStub();

	@Test
	public void testConstructor() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);

		ByteSourceRangeList list1 = new ByteSourceRangeList(range1);
		ByteSourceRangeList list2 = new ByteSourceRangeList();
		list2.add(range1);

		assertTrue(list1.equals(list2));
	}

	@Test
	public void testAdd() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x10, 2, 0x50);
		ByteSourceRangeList list1 = new ByteSourceRangeList(range1);
		ByteSourceRangeList list2 = new ByteSourceRangeList(range2);
		list1.add(list2);
		assertEquals(2, list1.getRangeCount());
		assertEquals(range1, list1.get(0));
		assertEquals(range2, list1.get(1));
	}

	@Test
	public void testIsEmpty() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRangeList list1 = new ByteSourceRangeList();

		assertTrue(list1.isEmpty());
		list1.add(range1);
		assertFalse(list1.isEmpty());
	}

	@Test
	public void testAddNullRange() {
		ByteSourceRange range = null;
		ByteSourceRangeList list1 = new ByteSourceRangeList();
		list1.add(range);
		assertTrue(list1.isEmpty());
	}

	@Test
	public void testIterator() {
		ByteSourceRange range1 = new ByteSourceRange(block, addr(0), 0x10, 1, 0x50);
		ByteSourceRange range2 = new ByteSourceRange(block, addr(0x100), 0x10, 2, 0x50);
		ByteSourceRangeList list1 = new ByteSourceRangeList(range1);
		list1.add(range2);
		
		Iterator<ByteSourceRange> it = list1.iterator();
		
		assertTrue(it.hasNext());
		assertEquals(range1, it.next());
		assertTrue(it.hasNext());
		assertEquals(range2, it.next());
		assertFalse(it.hasNext());
	}

	@Test
	public void testIntersectSimple() {
		ByteSourceRangeList list1 = new ByteSourceRangeList();
		list1.add(new ByteSourceRange(block, addr(0), 0x100, 1, 0));

		ByteSourceRangeList list2 = new ByteSourceRangeList();
		list2.add(new ByteSourceRange(block, addr(0x100), 0x100, 1, 0x10));

		// note that list1.intersect(list2) is not equal to list2.intersect(list1).
		// The byte sources are the same but the corresponding real addresses are calling
		// objects byte sources.

		ByteSourceRangeList result = list1.intersect(list2);
		assertEquals(1, result.getRangeCount());
		ByteSourceRange range = result.get(0);

		assertEquals(0xf0, range.getSize());
		assertEquals(0x10, range.getOffset());
		assertEquals(block, range.getMemoryBlock());
		assertEquals(1, range.getSourceId());
		assertEquals(addr(0x10), range.getStart());
		assertEquals(addr(0xff), range.getEnd());
		
		// now intersect from list2 perspective
		result = list2.intersect(list1);
		assertEquals(1, result.getRangeCount());
		range = result.get(0);

		assertEquals(0xf0, range.getSize());
		assertEquals(0x10, range.getOffset());
		assertEquals(block, range.getMemoryBlock());
		assertEquals(1, range.getSourceId());

		assertEquals(addr(0x100), range.getStart());
		assertEquals(addr(0x1ef), range.getEnd());

	}

	@Test
	public void testGetOverlappingBlocks() {
		ByteSourceRange range = new ByteSourceRange(block, addr(0), 0x100, 1, 0x00);
		MemoryBlock block1 = new MemoryBlockStub();
		ByteSourceRange range1 = new ByteSourceRange(block1, addr(0x100), 0x100, 2, 0x00);

		// create a byte source overlap with the first block
		MemoryBlock block2 = new MemoryBlockStub();
		ByteSourceRange range2 = new ByteSourceRange(block2, addr(0x200), 0x100, 1, 0x50);

		ByteSourceRangeList list = new ByteSourceRangeList();
		list.add(range);
		list.add(range1);
		list.add(range2);

		Set<MemoryBlock> overlappingBlocks = list.getOverlappingBlocks();
		assertEquals(2, overlappingBlocks.size());
		assertTrue(overlappingBlocks.contains(block));
		assertTrue(overlappingBlocks.contains(block2));
	}

	@Test
	public void testGetOverlappingBlocksBlocksWhereBlocksAreAdjacentButDontOverlap() {
		ByteSourceRange range = new ByteSourceRange(block, addr(0), 0x100, 1, 0x00);
		MemoryBlock block1 = new MemoryBlockStub();
		ByteSourceRange range1 = new ByteSourceRange(block1, addr(0x100), 0x100, 2, 0x00);

		// create a byte source overlap with the first block
		MemoryBlock block2 = new MemoryBlockStub();
		ByteSourceRange range2 = new ByteSourceRange(block2, addr(0x200), 0x100, 1, 0x100);

		ByteSourceRangeList list = new ByteSourceRangeList();
		list.add(range);
		list.add(range1);
		list.add(range2);

		Set<MemoryBlock> overlappingBlocks = list.getOverlappingBlocks();
		assertEquals(0, overlappingBlocks.size());
	}

	@Test
	public void testGetOverlappingBlocksBlocksWhereBlocksOverlapByExactlyOneByte() {
		ByteSourceRange range = new ByteSourceRange(block, addr(0), 0x100, 1, 0x00);
		MemoryBlock block1 = new MemoryBlockStub();
		ByteSourceRange range1 = new ByteSourceRange(block1, addr(0x100), 0x100, 2, 0x00);

		// create a byte source overlap with the first block
		MemoryBlock block2 = new MemoryBlockStub();
		ByteSourceRange range2 = new ByteSourceRange(block2, addr(0x200), 0x100, 1, 0xff);

		ByteSourceRangeList list = new ByteSourceRangeList();
		list.add(range);
		list.add(range1);
		list.add(range2);

		Set<MemoryBlock> overlappingBlocks = list.getOverlappingBlocks();
		assertEquals(2, overlappingBlocks.size());
		assertTrue(overlappingBlocks.contains(block));
		assertTrue(overlappingBlocks.contains(block2));
	}

	private Address addr(long value) {
		return space.getAddress(value);
	}

}
