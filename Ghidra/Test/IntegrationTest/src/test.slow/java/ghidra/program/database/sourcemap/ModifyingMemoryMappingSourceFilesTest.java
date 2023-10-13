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
package ghidra.program.database.sourcemap;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class ModifyingMemoryMappingSourceFilesTest extends AbstractSourceFileTest {

	protected SourceFileManagerDB sourceDB;
	private MemoryBlock textBlock;
	private Address blockStart;
	private Memory memory;

	@Before
	public void init() {
		sourceDB = (SourceFileManagerDB) sourceManager;
		textBlock = program.getMemory().getBlock(".text");
		blockStart = textBlock.getStart();
		memory = program.getMemory();
	}

	@Test(expected = AddressOverflowException.class)
	public void testAddingEntryWrappingSpace() throws LockException, IllegalArgumentException,
			MemoryConflictException, AddressOverflowException, CancelledException {
		Address spaceMin = blockStart.getAddressSpace().getMinAddress();
		Address spaceMax = blockStart.getAddressSpace().getMaxAddress();
		int txId = program.startTransaction("initializing memory");
		try {
			memory.createInitializedBlock("min", spaceMin, 10L, (byte) 0, TaskMonitor.DUMMY, false);
			memory.createInitializedBlock("max", spaceMax.subtract(10), 10, (byte) 0,
				TaskMonitor.DUMMY, false);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding wrapping entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, spaceMax.subtract(5), 10);
		}
		finally {
			program.endTransaction(txId, true);
		}

	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryCompletelyOutsideBlock()
			throws AddressOverflowException, LockException {
		Address start = textBlock.getStart().subtract(10);
		assertFalse(memory.intersects(start.subtract(10), start.subtract(5)));

		int txId = program.startTransaction("adding entry outside block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, start.subtract(10), 5);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingLengthZeroEntryOutsideBlock()
			throws AddressOverflowException, LockException {
		Address start = textBlock.getStart().subtract(10);
		assertFalse(memory.contains(start.subtract(10)));

		int txId = program.startTransaction("adding length 0 entry outside block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, start.subtract(10), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryUndefinedStart() throws AddressOverflowException, LockException {
		Address start = textBlock.getStart().subtract(5);
		assertFalse(memory.contains(start));

		int txId = program.startTransaction("adding entry with undefined start");
		try {
			sourceManager.addSourceMapEntry(source1, 1, start, 10);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryUndefinedEnd() throws LockException {
		Address end = textBlock.getEnd().add(5);
		assertFalse(memory.contains(end));

		int txId = program.startTransaction("adding entry with undefined end");
		try {
			sourceManager.addSourceMapEntry(source1, 1,
				new AddressRangeImpl(textBlock.getEnd().subtract(5), end));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntrySpanningUndefinedRange()
			throws MemoryBlockException, LockException, NotFoundException,
			AddressOverflowException {
		Address removeStart = blockStart.add(10);
		Address removeEnd = blockStart.add(15);
		assertTrue(memory.contains(removeStart, removeEnd));

		int txId = program.startTransaction("removing range");
		try {
			memory.split(textBlock, removeStart);
			MemoryBlock blockToSplit = memory.getBlock(removeStart);
			memory.split(blockToSplit, removeEnd.add(1));
			MemoryBlock blockToRemove = memory.getBlock(removeStart);
			memory.removeBlock(blockToRemove, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertFalse(memory.intersects(removeStart, removeEnd));

		txId = program.startTransaction("adding entry containing removed range");
		try {
			sourceManager.addSourceMapEntry(source1, 1, removeStart.subtract(5), 20);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testSetImageBase() throws AddressOverflowException, LockException {
		blockStart = textBlock.getStart();

		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart, 0x10);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(0x20), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("Setting image base");
		try {
			program.setImageBase(program.getImageBase().add(0x200000), true);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1);
		assertEquals(1, entries.size());
		SourceMapEntry entry = entries.get(0);
		assertEquals(source1, entry.getSourceFile());
		assertEquals(1, entry.getLineNumber());
		assertEquals(blockStart.add(0x200000), entry.getBaseAddress());
		assertEquals(0x10, entry.getLength());

		entries = sourceManager.getSourceMapEntries(source2);
		assertEquals(1, entries.size());
		entry = entries.get(0);
		assertEquals(source2, entry.getSourceFile());
		assertEquals(2, entry.getLineNumber());
		assertEquals(blockStart.add(0x200000).add(0x20), entry.getBaseAddress());
		assertEquals(0, entry.getLength());
	}

	@Test
	public void testAddingEntrySpanningAdjacentBlocks() throws MemoryBlockException, LockException,
			NotFoundException, AddressOutOfBoundsException, AddressOverflowException {
		blockStart = textBlock.getStart();

		int txId = program.startTransaction("splitting block");
		try {
			program.getMemory().split(textBlock, blockStart.add(20));
		}
		finally {
			program.endTransaction(txId, true);
		}

		MemoryBlock leftBlock = program.getMemory().getBlock(blockStart);
		txId = program.startTransaction("splitting left block");
		try {
			program.getMemory().split(leftBlock, blockStart.add(10));
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(5), 40);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1);
		assertEquals(1, entries.size());
		SourceMapEntry entry = entries.get(0);
		assertEquals(source1, entry.getSourceFile());
		assertEquals(1, entry.getLineNumber());
		assertEquals(blockStart.add(5), entry.getBaseAddress());
		assertEquals(40, entry.getLength());
	}

	@Test
	public void testSplittingBlockContainingEntry()
			throws AddressOverflowException, LockException, MemoryBlockException, NotFoundException,
			AddressOutOfBoundsException {

		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(5), 20);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("splitting block");
		try {
			program.getMemory().split(textBlock, blockStart.add(10));
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1);
		assertEquals(1, entries.size());
		SourceMapEntry entry = entries.get(0);
		assertEquals(source1, entry.getSourceFile());
		assertEquals(1, entry.getLineNumber());
		assertEquals(blockStart.add(5), entry.getBaseAddress());
		assertEquals(20, entry.getLength());
	}

	private void setUpNoEntriesInRegionTest()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(5), 3);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(5), 3);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(7), 0);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(25), 6);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(25), 6);
			sourceManager.addSourceMapEntry(source3, 33, blockStart.add(27), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void checkNoEntriesInRegion() {

		assertEquals(2, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 3);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(25), 6);

		assertEquals(2, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 3);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(25), 6);

		assertEquals(2, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(7), 0);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(27), 0);
	}

	private void checkBaseAddressAndLength(SourceMapEntry entry, Address baseAddr, long length) {
		assertEquals(baseAddr, entry.getBaseAddress());
		assertEquals(length, entry.getLength());
	}


	@Test
	public void testMovingRegionWithNoEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpNoEntriesInRegionTest();
		int txId = program.startTransaction("moving region");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x50000), 10,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		checkNoEntriesInRegion();
	}

	@Test
	public void testDeletingRegionWithNoEntries() throws AddressOverflowException, LockException,
			AddressOutOfBoundsException, CancelledException {
		setUpNoEntriesInRegionTest();
		int txId = program.startTransaction("deleting region");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(20), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		checkNoEntriesInRegion();
	}

	private void setUpRegionContainingEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {

		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(10 + 1), 2);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(10 + 1), 2);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(10 + 2), 0);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(10 + 6), 3);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(10 + 6), 3);
			sourceManager.addSourceMapEntry(source3, 33, blockStart.add(10 + 7), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingRegionContainingEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpRegionContainingEntries();
		
		int txId = program.startTransaction("moving region");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 10,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(2, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 1), 2);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 6), 3);

		assertEquals(2, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 1), 2);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 6), 3);

		assertEquals(2, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 2), 0);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000 + 7), 0);

	}

	@Test
	public void testDeletingRegionContainingEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpRegionContainingEntries();

		int txId = program.startTransaction("deleting region");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(20), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(0, sourceManager.getMappedSourceFiles().size());
		assertEquals(0, sourceManager.getSourceMapEntries(source1).size());
		assertEquals(0, sourceManager.getSourceMapEntries(source2).size());
		assertEquals(0, sourceManager.getSourceMapEntries(source3).size());
	}

	private void setUpOverlappingStart()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(5), 10);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(5), 10);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(5), 10);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(5), 10);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingRegionWithEntryOverlappingStart()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpOverlappingStart();
		int txId = program.startTransaction("moving region");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 10,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 5);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 5);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 5);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 5);

	}

	@Test
	public void testDeletingRegionWithEntryOverlappingStart()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpOverlappingStart();
		int txId = program.startTransaction("deleting region");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(100), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);

	}

	private void setUpOverlappingEnd()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(15), 10);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(15), 10);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(15), 10);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(15), 10);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingRegionWithEntryOverlappingEnd()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpOverlappingEnd();

		int txId = program.startTransaction("moving region");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 10,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100005), 5);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100005), 5);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100005), 5);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100005), 5);
	}

	@Test
	public void testDeletingRegionWithEntryOverlappingEnd()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpOverlappingEnd();

		int txId = program.startTransaction("deleting range");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(20), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(21), 4);
	}

	private void setUpContainingRegion()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(5), 20);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(5), 20);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(5), 20);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(5), 20);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingRegionContainedWithinEntry()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpContainingRegion();

		int txId = program.startTransaction("moving region");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 10,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(3, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(2), blockStart.add(0x100000), 10);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(3, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(2), blockStart.add(0x100000), 10);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(3, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(2), blockStart.add(0x100000), 10);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(3, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(20), 5);
		checkBaseAddressAndLength(entries.get(2), blockStart.add(0x100000), 10);
	}

	@Test
	public void testDeletingRegionContainedWithinEntry()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpContainingRegion();

		int txId = program.startTransaction("deleting region");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(20), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(21), 4);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(5), 5);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(21), 4);
	}

	private void setUpLengthZeroEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(9), 0);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(9), 0);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(9), 0);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(10), 0);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(10), 0);
			sourceManager.addSourceMapEntry(source3, 33, blockStart.add(10), 0);
			sourceManager.addSourceMapEntry(source1, 111, blockStart.add(11), 0);
			sourceManager.addSourceMapEntry(source2, 222, blockStart.add(11), 0);
			sourceManager.addSourceMapEntry(source3, 333, blockStart.add(11), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingOneAddressLengthZeroEntries()
			throws AddressOverflowException, CancelledException, AddressOutOfBoundsException,
			LockException {
		setUpLengthZeroEntries();
		int txId = program.startTransaction("moving address");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 1,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		assertEquals(3, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 0);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);

		assertEquals(3, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 0);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);

		assertEquals(3, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 0);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);
	}

	@Test
	public void testDeletingOneAddressLengthZeroEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthZeroEntries();
		int txId = program.startTransaction("deleting range");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(10), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		assertEquals(2, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);

		assertEquals(2, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);

		assertEquals(2, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 0);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 0);
	}

	private void setUpLengthOneEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(9), 1);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(9), 1);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(9), 1);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(10), 1);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(10), 1);
			sourceManager.addSourceMapEntry(source3, 33, blockStart.add(10), 1);
			sourceManager.addSourceMapEntry(source1, 111, blockStart.add(11), 1);
			sourceManager.addSourceMapEntry(source2, 222, blockStart.add(11), 1);
			sourceManager.addSourceMapEntry(source3, 333, blockStart.add(11), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMoveOneAddressLengthOneEntries()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthOneEntries();

		int txId = program.startTransaction("moving address");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 1,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		assertEquals(3, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		assertEquals(3, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		assertEquals(3, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
	}

	@Test
	public void testDeleteOneAddressLengthOneEntries() throws AddressOverflowException,
			LockException, AddressOutOfBoundsException, CancelledException {
		setUpLengthOneEntries();
		int txId = program.startTransaction("deleting range");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(10), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		assertEquals(2, sourceManager.getSourceMapEntries(source1).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		assertEquals(2, sourceManager.getSourceMapEntries(source2).size());

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		assertEquals(2, sourceManager.getSourceMapEntries(source3).size());

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
	}

	private void setUpLengthTwoEntries1()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(9), 2);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(9), 2);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(9), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMoveOneAddressLengthTwoEntries1()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthTwoEntries1();
		int txId = program.startTransaction("moving address");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 1,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);
	}

	@Test
	public void testDeletingOneAddressLength2Entries1()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthTwoEntries1();
		int txId = program.startTransaction("deleting address");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(10), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9), 1);
	}

	private void setUpLengthTwoEntries2()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(10), 2);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(10), 2);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(10), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMoveOneAddressLengthTwoEntries2()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthTwoEntries2();
		int txId = program.startTransaction("moving address");
		try {
			sourceDB.moveAddressRange(blockStart.add(10), blockStart.add(0x100000), 1,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(2, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
		checkBaseAddressAndLength(entries.get(1), blockStart.add(0x100000), 1);
	}

	@Test
	public void testDeletingOneAddressLength2Entries2()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpLengthTwoEntries2();
		int txId = program.startTransaction("deleting address");
		try {
			sourceDB.deleteAddressRange(blockStart.add(10), blockStart.add(10), TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11), 1);
	}

	private void setUpMovingRangeIntersection()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException {
		int txId = program.startTransaction("adding new blentries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blockStart.add(8), 2);
			sourceManager.addSourceMapEntry(source2, 2, blockStart.add(8), 2);
			sourceManager.addSourceMapEntry(source3, 3, blockStart.add(9), 0);
			sourceManager.addSourceMapEntry(source1, 11, blockStart.add(10), 2);
			sourceManager.addSourceMapEntry(source2, 22, blockStart.add(10), 2);
			sourceManager.addSourceMapEntry(source3, 33, blockStart.add(11), 0);
			sourceManager.addSourceMapEntry(source1, 111, blockStart.add(12), 2);
			sourceManager.addSourceMapEntry(source2, 222, blockStart.add(12), 2);
			sourceManager.addSourceMapEntry(source3, 333, blockStart.add(13), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMovingIntersectionRangesForward()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpMovingRangeIntersection();
		int txId = program.startTransaction("moving block");
		try {
			sourceDB.moveAddressRange(blockStart, blockStart.add(3), textBlock.getSize(),
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(8 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(10 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(12 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(8 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(10 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(12 + 3), 2);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9 + 3), 0);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11 + 3), 0);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(13 + 3), 0);
	}

	@Test
	public void testMovingIntersectionRangesBackward()
			throws AddressOverflowException, LockException, AddressOutOfBoundsException,
			CancelledException {
		setUpMovingRangeIntersection();
		int txId = program.startTransaction("moving block");
		try {
			sourceDB.moveAddressRange(blockStart, blockStart.subtract(3), textBlock.getSize(),
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals(3, sourceManager.getMappedSourceFiles().size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(source1, 1);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(8 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source1, 11);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(10 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source1, 111);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(12 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 2);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(8 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 22);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(10 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source2, 222);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(12 - 3), 2);

		entries = sourceManager.getSourceMapEntries(source3, 3);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(9 - 3), 0);

		entries = sourceManager.getSourceMapEntries(source3, 33);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(11 - 3), 0);

		entries = sourceManager.getSourceMapEntries(source3, 333);
		assertEquals(1, entries.size());
		checkBaseAddressAndLength(entries.get(0), blockStart.add(13 - 3), 0);

	}


}
