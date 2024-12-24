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

import java.io.IOException;
import java.util.HexFormat;
import java.util.List;

import org.junit.Test;
import org.python.google.common.primitives.Longs;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.util.SourceFileUtils;
import ghidra.util.SourceFileUtils.SourceLineBounds;

public class MappingSourceFilesTest extends AbstractSourceFileTest {

	@Test
	public void testNoSourceInfo() {
		assertTrue(sourceManager.getMappedSourceFiles().isEmpty());
		assertEquals(3, sourceManager.getAllSourceFiles().size());
		assertTrue(sourceManager.getSourceMapEntries(ret2_1.getAddress()).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(source1).isEmpty());
	}

	@Test
	public void testMappingDummySourceManager() {
		sourceManager = SourceFileManager.DUMMY;
		assertTrue(sourceManager.getMappedSourceFiles().isEmpty());
		assertTrue(sourceManager.getAllSourceFiles().isEmpty());

		assertTrue(sourceManager.getSourceMapEntries(ret2_1.getMinAddress()).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(source1, 1, 1).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(source1, 0, Integer.MAX_VALUE).isEmpty());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeLength() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), -1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = NullPointerException.class)
	public void testAddingEntryNullSourceFile() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(null, 1, ret2_1.getAddress(), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = NullPointerException.class)
	public void testRemovingNullSourceMapEntry() throws LockException {
		int txId = program.startTransaction("removing source map entry");
		try {
			sourceManager.removeSourceMapEntry(null);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testGetSourceInfoNullAddress() {
		assertTrue(sourceManager.getSourceMapEntries((Address) null).isEmpty());
	}

	@Test
	public void testGetSourceInfoNoAddress() {
		assertTrue(sourceManager.getSourceMapEntries(Address.NO_ADDRESS).isEmpty());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSettingNegativeLineNumber() throws LockException {

		int txId = program.startTransaction("setting bad line number info");
		try {
			sourceManager.addSourceMapEntry(source1, -1, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeMinline() {
		sourceManager.getSourceMapEntries(source1, -1, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeMaxline() {
		sourceManager.getSourceMapEntries(source1, 1, -1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testMaxLineLessThanMin() {
		sourceManager.getSourceMapEntries(source1, 10, 5);
	}

	@Test
	public void testAddingSameEntryTwice() throws LockException {

		int txId = program.startTransaction("adding source map entry");
		SourceMapEntry entry = null;
		try {
			entry = sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding redundant source map info");
		SourceMapEntry entry2 = null;
		try {
			entry2 = sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(entry, entry2);
		assertEquals(1, sourceManager.getSourceMapEntries(source1).size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingSimilarEntriesDifferentLengths()
			throws LockException, AddressOverflowException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding incompatible source map info");

		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testAddingSameLengthZeroEntryTwice()
			throws LockException, AddressOverflowException {

		int txId = program.startTransaction("adding source map entry");
		SourceMapEntry entry = null;
		try {
			entry = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding redundant source map info");
		SourceMapEntry entry2 = null;
		try {
			entry2 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(entry, entry2);
		assertEquals(1, sourceManager.getSourceMapEntries(source1).size());
	}

	@Test
	public void simpleSettingGettingTest() throws LockException, IOException {
		assertTrue(sourceManager.getMappedSourceFiles().isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(ret2_1.getAddress()).isEmpty());

		int txId = program.startTransaction("adding source map entry");
		SourceMapEntry source1Entry = null;
		try {
			source1Entry = sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(2, source1Entry.getLength());
		assertEquals(1, source1Entry.getLineNumber());
		assertEquals(getBody(ret2_1), source1Entry.getRange());
		assertEquals(source1, source1Entry.getSourceFile());

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1));
		assertEquals(1, entries.size());
		entries = sourceManager.getSourceMapEntries(nop1_1.getAddress());
		assertEquals(0, entries.size());

		txId = program.startTransaction("adding source map entry");
		SourceMapEntry source2Entry = null;
		try {
			source2Entry = sourceManager.addSourceMapEntry(source2, 2, getBody(ret2_2));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source2));

		List<SourceMapEntry> entries1 = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries1.size());
		assertEquals(source1Entry, entries1.get(0));

		List<SourceMapEntry> entries2 = sourceManager.getSourceMapEntries(ret2_2.getAddress());
		assertEquals(1, entries2.size());
		assertEquals(source2Entry, entries2.get(0));

		program.undo();
		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1));
		assertEquals(1, entries.size());
		entries = sourceManager.getSourceMapEntries(nop1_1.getAddress());
		assertEquals(0, entries.size());

	}

	@Test
	public void testMultipleEntriesOneAddress() throws LockException {
		assertTrue(sourceManager.getSourceMapEntries(ret2_1.getAddress()).isEmpty());
		AddressRange range = getBody(ret2_1);

		SourceMapEntry entry_1_1 = null;
		SourceMapEntry entry_1_2 = null;
		SourceMapEntry entry_2_1 = null;

		int txId = program.startTransaction("adding first source map entry");
		try {
			entry_1_1 = sourceManager.addSourceMapEntry(source1, 1, range);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().subtract(1)).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		assertTrue(entries.contains(entry_1_1));

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1));
		assertEquals(1, entries.size());
		assertTrue(entries.contains(entry_1_1));

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().add(2)).size());

		txId = program.startTransaction("adding second source map entry");
		try {
			entry_1_2 = sourceManager.addSourceMapEntry(source1, 2, range);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().subtract(1)).size());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry_1_1));
		assertTrue(entries.contains(entry_1_2));

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1));
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry_1_1));
		assertTrue(entries.contains(entry_1_2));

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().add(2)).size());

		txId = program.startTransaction("adding third source map entry");
		try {
			entry_2_1 = sourceManager.addSourceMapEntry(source2, 1, range);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().subtract(1)).size());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(3, entries.size());
		assertTrue(entries.contains(entry_1_1));
		assertTrue(entries.contains(entry_1_2));
		assertTrue(entries.contains(entry_2_1));

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1));
		assertEquals(3, entries.size());
		assertTrue(entries.contains(entry_1_1));
		assertTrue(entries.contains(entry_1_2));
		assertTrue(entries.contains(entry_2_1));

		assertEquals(0, sourceManager.getSourceMapEntries(ret2_1.getAddress().add(2)).size());

	}

	@Test
	public void testAddingLengthZeroEntries() throws AddressOverflowException, LockException {
		assertTrue(sourceManager.getSourceMapEntries(ret2_1.getAddress()).isEmpty());
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		SourceMapEntry entry3 = null;
		SourceMapEntry entry4 = null;

		int txId = program.startTransaction("adding first source map entry");
		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding length zero entry");
		try {
			entry2 = sourceManager.addSourceMapEntry(source1, 2, ret2_1.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertNull(entry2.getRange());

		txId = program.startTransaction("adding length zero entry");
		try {
			entry3 = sourceManager.addSourceMapEntry(source1, 3, ret2_1.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding length zero entry");
		try {
			entry4 = sourceManager.addSourceMapEntry(source1, 4, ret2_1.getAddress().add(1L), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> containingEntries =
			sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(3, containingEntries.size());
		assertTrue(containingEntries.contains(entry1));
		assertTrue(containingEntries.contains(entry2));
		assertTrue(containingEntries.contains(entry3));

		containingEntries = sourceManager.getSourceMapEntries(ret2_1.getAddress().add(1L));
		assertEquals(2, containingEntries.size());
		assertTrue(containingEntries.contains(entry1));
		assertTrue(containingEntries.contains(entry4));
	}

	@Test
	public void testRemovingEntries() throws LockException, IOException {

		Address min = ret2_1.getMinAddress();
		Address max = ret2_1.getMaxAddress();
		AddressRange range = new AddressRangeImpl(min, max);
		SourceMapEntry entry = null;

		int txId = program.startTransaction("adding source map entry");
		try {
			entry = sourceManager.addSourceMapEntry(source1, 1, range);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(entry);
		assertEquals(1, sourceManager.getSourceMapEntries(min).size());
		assertEquals(1, sourceManager.getSourceMapEntries(max).size());

		txId = program.startTransaction("removing source map entry");
		try {
			assertTrue(sourceManager.removeSourceMapEntry(entry));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertTrue(sourceManager.getSourceMapEntries(min).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(max).isEmpty());

		program.undo();
		assertEquals(1, sourceManager.getSourceMapEntries(min).size());
		assertEquals(1, sourceManager.getSourceMapEntries(max).size());

		program.redo();
		assertTrue(sourceManager.getSourceMapEntries(min).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(max).isEmpty());
	}

	public void testRemovingRemovedWithLengthZero() throws AddressOverflowException, LockException {
		SourceMapEntry entry = null;

		int txId = program.startTransaction("adding source map entries");
		try {
			entry = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("removing source map entry");
		try {
			assertTrue(sourceManager.removeSourceMapEntry(entry));
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("removing source map entry");
		try {
			assertFalse(sourceManager.removeSourceMapEntry(entry));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingConflictingEntries() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding conflicting source map info");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 3);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingOverlappingEntrySameSourceInfoBefore()
			throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_2.getAddress(), ret2_2.getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding overlapping source map info");
		try {
			sourceManager.addSourceMapEntry(source1, 1, nop1_1.getAddress(),
				nop1_1.getLength() + 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingOverlappingEntryDifferentSourceInfoBefore()
			throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_2.getAddress(), ret2_2.getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding overlapping source map info");
		try {
			sourceManager.addSourceMapEntry(source2, 2, nop1_1.getAddress(),
				nop1_1.getLength() + 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingOverlappingEntrySameSourceInfoAfter()
			throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(),
				ret2_1.getLength() + 1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding overlapping source map info");
		try {
			sourceManager.addSourceMapEntry(source1, 1, nop1_1.getAddress(), nop1_1.getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingOverlappingEntryDifferentSourceInfoAfter()
			throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(),
				ret2_1.getLength() + 1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		txId = program.startTransaction("adding overlapping source map info");
		try {
			sourceManager.addSourceMapEntry(source2, 2, nop1_1.getAddress(), nop1_1.getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testAdjacentEntries() throws LockException, AddressOverflowException {
		int txId = program.startTransaction("setting source map info");
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		SourceMapEntry entry3 = null;
		SourceMapEntry entry4 = null;
		SourceMapEntry entry5 = null;
		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_2));
			entry2 = sourceManager.addSourceMapEntry(source1, 2, getBody(nop1_2));
			entry3 = sourceManager.addSourceMapEntry(source2, 3, ret2_2.getAddress(), 0);
			entry4 = sourceManager.addSourceMapEntry(source3, 4, ret2_2.getAddress().add(1), 0);
			entry5 = sourceManager.addSourceMapEntry(source2, 5, nop1_2.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(ret2_2.getAddress());
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry3));

		entries = sourceManager.getSourceMapEntries(ret2_2.getAddress().add(1));
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry4));

		assertEquals(ret2_2.getAddress().add(2), nop1_2.getAddress());
		entries = sourceManager.getSourceMapEntries(nop1_2.getAddress());
		assertTrue(entries.contains(entry2));
		assertTrue(entries.contains(entry5));

		entries = sourceManager.getSourceMapEntries(ret2_2.getAddress().subtract(1));
		assertEquals(0, entries.size());

		entries = sourceManager.getSourceMapEntries(nop1_2.getAddress().add(1));
		assertEquals(0, entries.size());
	}

	@Test
	public void testClearingAllEntriesForOneSourceFile() throws LockException {

		int txId = program.startTransaction("setting source map info");
		SourceMapEntry source1Entry = null;
		SourceMapEntry source3Entry = null;
		try {
			source1Entry = sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
			sourceManager.addSourceMapEntry(source2, 2, getBody(ret2_2));
			source3Entry = sourceManager.addSourceMapEntry(source3, 3, getBody(ret2_3));
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(3, sourceFiles.size());

		List<SourceMapEntry> source2Entries =
			sourceManager.getSourceMapEntries(source2, 0, Integer.MAX_VALUE);
		assertEquals(1, source2Entries.size());
		List<SourceMapEntry> source2EntriesRestricted =
			sourceManager.getSourceMapEntries(source2, 2, 2);
		assertEquals(1, source2EntriesRestricted.size());
		assertEquals(source2Entries.get(0), source2EntriesRestricted.get(0));
		assertTrue(sourceManager.getSourceMapEntries(source1, 4, 5).isEmpty());

		txId = program.startTransaction("clearing source info for source2");
		try {
			for (SourceMapEntry entry : source2Entries) {
				assertTrue(sourceManager.removeSourceMapEntry(entry));
			}
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertFalse(sourceFiles.contains(source2));

		assertEquals(1, sourceManager.getSourceMapEntries(ret2_1.getAddress()).size());
		assertEquals(source1Entry, sourceManager.getSourceMapEntries(ret2_1.getAddress()).get(0));
		assertTrue(sourceManager.getSourceMapEntries(ret2_2.getAddress()).isEmpty());
		assertEquals(1, sourceManager.getSourceMapEntries(ret2_3.getAddress()).size());
		assertEquals(source3Entry, sourceManager.getSourceMapEntries(ret2_3.getAddress()).get(0));
	}

	@Test
	public void testDeletingSourceFile() throws LockException, IOException {

		SourceMapEntry entry2 = null;
		int txId = program.startTransaction("setting source map info");
		try {
			sourceManager.addSourceMapEntry(source1, 1, getBody(ret2_1));
			entry2 = sourceManager.addSourceMapEntry(source2, 2, getBody(ret2_2));
			sourceManager.addSourceMapEntry(source1, 3, getBody(ret2_1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source2));

		List<SourceMapEntry> source2Entries =
			sourceManager.getSourceMapEntries(ret2_2.getAddress());
		assertEquals(1, source2Entries.size());
		assertEquals(entry2, source2Entries.get(0));

		txId = program.startTransaction("deleting source file");
		try {
			assertTrue(sourceManager.removeSourceFile(source2));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		SourceFile mappedFile = sourceFiles.get(0);
		assertEquals(source1, mappedFile);
		assertTrue(sourceManager.getSourceMapEntries(ret2_2.getAddress()).isEmpty());

		// undo delete and verify that everything is restored
		program.undo();
		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(source1));
		assertTrue(sourceFiles.contains(source2));

		assertEquals(1, sourceManager.getSourceMapEntries(ret2_2.getAddress()).size());
		SourceMapEntry sourceInfo = sourceManager.getSourceMapEntries(ret2_2.getAddress()).get(0);
		assertEquals(2, sourceInfo.getLineNumber());
		assertEquals(source2, sourceInfo.getSourceFile());

		// redo delete and verify
		program.redo();
		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertEquals(source1, sourceFiles.get(0));
		assertTrue(sourceManager.getSourceMapEntries(ret2_2.getAddress()).isEmpty());
	}

	@Test
	public void testTransferringSourceMapInfo() throws LockException {
		assertTrue(sourceManager.getMappedSourceFiles().isEmpty());

		AddressRange both = new AddressRangeImpl(ret2_1.getMinAddress(), ret2_2.getMaxAddress());

		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, both);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertEquals(source1, sourceFiles.get(0));
		assertEquals(1, sourceManager.getSourceMapEntries(source1).size());
		assertTrue(sourceManager.getSourceMapEntries(source2).isEmpty());

		// test redundant transfer
		txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source1, new SourceFile(path1));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertEquals(source1, sourceFiles.get(0));
		assertEquals(1, sourceManager.getSourceMapEntries(source1).size());
		assertTrue(sourceManager.getSourceMapEntries(source2).isEmpty());

		txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source1, source2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertEquals(source2, sourceFiles.get(0));
		assertTrue(sourceManager.getSourceMapEntries(source1).isEmpty());
		assertEquals(1, sourceManager.getSourceMapEntries(source2).size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		SourceMapEntry entry = entries.get(0);
		assertEquals(source2, entry.getSourceFile());
		assertEquals(1, entry.getLineNumber());
		assertEquals(both, entry.getRange());

		// test transfer of files with no source map entries
		assertEquals(0, sourceManager.getSourceMapEntries(source1).size());
		assertEquals(1, sourceManager.getSourceMapEntries(source2).size());
		assertEquals(0, sourceManager.getSourceMapEntries(source3).size());
		txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source3, source1);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals(0, sourceManager.getSourceMapEntries(source1).size());
		assertEquals(1, sourceManager.getSourceMapEntries(source2).size());
		assertEquals(0, sourceManager.getSourceMapEntries(source3).size());
	}

	@Test
	public void testIntersectsSourceFileEntry() throws LockException, AddressOverflowException {
		assertTrue(sourceManager.getMappedSourceFiles().isEmpty());
		AddressSet everything = program.getAddressFactory().getAddressSet();
		assertFalse(sourceManager.intersectsSourceMapEntry(everything));
		assertFalse(sourceManager.intersectsSourceMapEntry(null));
		assertFalse(sourceManager.intersectsSourceMapEntry(new AddressSet()));
		assertFalse(sourceManager.intersectsSourceMapEntry(new AddressSet(Address.NO_ADDRESS)));

		int txId = program.startTransaction("setting source map info");
		try {
			sourceManager.addSourceMapEntry(source2, 2, ret2_2.getAddress(), 0);
			sourceManager.addSourceMapEntry(source3, 3, getBody(ret2_3));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertTrue(sourceManager.intersectsSourceMapEntry(everything));
		assertFalse(sourceManager.intersectsSourceMapEntry(new AddressSet(Address.NO_ADDRESS)));
		assertFalse(sourceManager.intersectsSourceMapEntry(null));
		assertFalse(sourceManager.intersectsSourceMapEntry(new AddressSet()));

		// test with a length 0 entry
		assertFalse(sourceManager
				.intersectsSourceMapEntry(new AddressSet(ret2_2.getAddress().subtract(1))));
		assertTrue(sourceManager.intersectsSourceMapEntry(new AddressSet(ret2_2.getAddress())));
		assertFalse(
			sourceManager.intersectsSourceMapEntry(new AddressSet(ret2_2.getAddress().add(1))));

		assertFalse(sourceManager
				.intersectsSourceMapEntry(new AddressSet(ret2_3.getAddress().subtract(1))));
		assertTrue(sourceManager.intersectsSourceMapEntry(new AddressSet(ret2_3.getAddress())));
		assertTrue(
			sourceManager.intersectsSourceMapEntry(new AddressSet(ret2_3.getAddress().add(1))));
		assertFalse(
			sourceManager.intersectsSourceMapEntry(new AddressSet(ret2_3.getAddress().add(2))));

		assertTrue(sourceManager.intersectsSourceMapEntry(new AddressSet(getBody(ret2_3))));

	}

	@Test
	public void testSourceLineBounds() throws AddressOverflowException, LockException {
		assertNull(SourceFileUtils.getSourceLineBounds(program, source1));
		assertNull(SourceFileUtils.getSourceLineBounds(program, source2));
		assertNull(SourceFileUtils.getSourceLineBounds(program, source3));

		int txId = program.startTransaction("Adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 10, ret2_1.getAddress(), 4);
		}
		finally {
			program.endTransaction(txId, true);
		}

		SourceLineBounds bounds = SourceFileUtils.getSourceLineBounds(program, source1);
		assertEquals(10, bounds.min());
		assertEquals(10, bounds.max());
		assertNull(SourceFileUtils.getSourceLineBounds(program, source2));
		assertNull(SourceFileUtils.getSourceLineBounds(program, source3));

		txId = program.startTransaction("Adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 5, ret2_1.getAddress(), 4);
		}
		finally {
			program.endTransaction(txId, true);
		}

		bounds = SourceFileUtils.getSourceLineBounds(program, source1);
		assertEquals(5, bounds.min());
		assertEquals(10, bounds.max());
		assertNull(SourceFileUtils.getSourceLineBounds(program, source2));
		assertNull(SourceFileUtils.getSourceLineBounds(program, source3));

		txId = program.startTransaction("Adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 20, ret2_3.getAddress(), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}

		bounds = SourceFileUtils.getSourceLineBounds(program, source1);
		assertEquals(5, bounds.min());
		assertEquals(20, bounds.max());
		assertNull(SourceFileUtils.getSourceLineBounds(program, source2));
		assertNull(SourceFileUtils.getSourceLineBounds(program, source3));
	}

	@Test
	public void testUniquenessAfterTransfer() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("Adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 10, ret2_1.getAddress(), 4);
			sourceManager.addSourceMapEntry(source2, 10, ret2_1.getAddress(), 4);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertEquals(2, sourceManager.getSourceMapEntries(ret2_1.getAddress()).size());

		txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source1, source2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(1, sourceManager.getSourceMapEntries(ret2_1.getAddress()).size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAddingEntryBeforeAddingFile() throws AddressOverflowException, LockException {
		SourceFile sourceFile = new SourceFile("/src/test/file123.cc");
		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(sourceFile, 1, ret2_1.getAddress(), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransferringSourceFileInfoSourceNotAdded() throws LockException {
		SourceFile sourceFile = new SourceFile("/src/test/file123.cc");
		int txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(sourceFile, source1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransferringSourceFileInfoTargetNotAdded() throws LockException {
		SourceFile sourceFile = new SourceFile("/src/test/file123.cc");
		int txId = program.startTransaction("transferring source map entries");
		try {
			sourceManager.transferSourceMapEntries(source1, sourceFile);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testMappingSamePathDifferentIdentifiers()
			throws AddressOverflowException, LockException {
		HexFormat hexFormat = HexFormat.of();
		assertEquals(3, sourceManager.getAllSourceFiles().size());
		String path = "/src/test/file.c";
		SourceFile test1 = new SourceFile(path);
		SourceFile test2 = new SourceFile(path, SourceFileIdType.MD5,
			hexFormat.parseHex("0123456789abcdef0123456789abcdef"));
		SourceFile test3 =
			new SourceFile(path, SourceFileIdType.TIMESTAMP_64, Longs.toByteArray(0));
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		SourceMapEntry entry3 = null;

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(0, sourceFiles.size());

		List<SourceMapEntry> entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(0, entries.size());

		int txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceFile(test1);
			entry1 = sourceManager.addSourceMapEntry(test1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertEquals(test1, sourceFiles.get(0));

		assertEquals(1, sourceManager.getSourceMapEntries(test1).size());
		assertTrue(sourceManager.getSourceMapEntries(test2).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(test3).isEmpty());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		assertEquals(entry1, entries.get(0));

		txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceFile(test2);
			entry2 = sourceManager.addSourceMapEntry(test2, 2, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(test1));
		assertTrue(sourceFiles.contains(test2));

		assertEquals(1, sourceManager.getSourceMapEntries(test1).size());
		assertEquals(1, sourceManager.getSourceMapEntries(test2).size());
		assertTrue(sourceManager.getSourceMapEntries(test3).isEmpty());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry2));

		txId = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceFile(test3);
			entry3 = sourceManager.addSourceMapEntry(test3, 3, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(3, sourceFiles.size());
		assertTrue(sourceFiles.contains(test1));
		assertTrue(sourceFiles.contains(test2));
		assertTrue(sourceFiles.contains(test3));

		assertEquals(1, sourceManager.getSourceMapEntries(test1).size());
		assertEquals(1, sourceManager.getSourceMapEntries(test2).size());
		assertEquals(1, sourceManager.getSourceMapEntries(test3).size());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(3, entries.size());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry2));
		assertTrue(entries.contains(entry3));

		txId = program.startTransaction("removing source map entry");
		try {
			assertTrue(sourceManager.removeSourceMapEntry(entry3));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(2, sourceFiles.size());
		assertTrue(sourceFiles.contains(test1));
		assertTrue(sourceFiles.contains(test2));

		assertEquals(1, sourceManager.getSourceMapEntries(test1).size());
		assertEquals(1, sourceManager.getSourceMapEntries(test2).size());
		assertTrue(sourceManager.getSourceMapEntries(test3).isEmpty());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(2, entries.size());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry2));

		txId = program.startTransaction("removing source file");
		try {
			assertTrue(sourceManager.removeSourceFile(test2));
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getMappedSourceFiles();
		assertEquals(1, sourceFiles.size());
		assertTrue(sourceFiles.contains(test1));

		assertEquals(1, sourceManager.getSourceMapEntries(test1).size());
		assertTrue(sourceManager.getSourceMapEntries(test2).isEmpty());
		assertTrue(sourceManager.getSourceMapEntries(test3).isEmpty());

		entries = sourceManager.getSourceMapEntries(ret2_1.getAddress());
		assertEquals(1, entries.size());
		assertTrue(entries.contains(entry1));
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryAfterBlocks()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding entry after block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getEnd().add(0x10), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingLengthZeroEntryAfterBlocks()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding length zero entry after block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getEnd().add(0x10), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryOverlappingEndOfBlock()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding entry overlapping block end");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getEnd().subtract(5),10);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryBeforeBlocks()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding entry after block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getStart().subtract(0x10), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingLengthZeroEntryBeforeBlocks()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding length zero entry after block");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getStart().subtract(0x10), 0);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = AddressOutOfBoundsException.class)
	public void testAddingEntryOverlappingStartOfBlock()
			throws AddressOverflowException, LockException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		int txId = program.startTransaction("adding entry overlapping block end");
		try {
			sourceManager.addSourceMapEntry(source1, 1, blocks[0].getStart().subtract(5), 10);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}



}
