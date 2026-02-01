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

import java.util.*;

import org.junit.Test;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.sourcemap.*;

public class SourceMapEntryIteratorTest extends AbstractSourceFileTest {

	@Test
	public void testInappropriateAddress() {
		assertFalse(sourceManager.getSourceMapEntryIterator(null, true).hasNext());
		assertFalse(sourceManager.getSourceMapEntryIterator(null, false).hasNext());
		assertFalse(sourceManager.getSourceMapEntryIterator(Address.NO_ADDRESS, true).hasNext());
		assertFalse(sourceManager.getSourceMapEntryIterator(Address.NO_ADDRESS, false).hasNext());
	}

	@Test
	public void testDummySourceManagerIterators() {
		Address address = ret2_1.getAddress();
		assertFalse(
			SourceFileManager.DUMMY.getSourceMapEntryIterator(address, true).hasNext());
		assertFalse(
			SourceFileManager.DUMMY.getSourceMapEntryIterator(address, false).hasNext());
	}

	@Test(expected = NoSuchElementException.class)
	public void testNoSuchElementExceptionForward() throws AddressOverflowException, LockException {
		SourceMapEntry entry1 = null;

		int txId = program.startTransaction("adding source map entry");
		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		SourceMapEntryIterator iter =
			sourceManager.getSourceMapEntryIterator(ret2_1.getAddress(), true);
		assertTrue(iter.hasNext());
		assertEquals(entry1, iter.next());
		assertFalse(iter.hasNext());
		iter.next();
	}

	@Test(expected = NoSuchElementException.class)
	public void testNoSuchElementExceptionBackward()
			throws AddressOverflowException, LockException {
		SourceMapEntry entry1 = null;

		int txId = program.startTransaction("adding source map entry");
		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		SourceMapEntryIterator iter =
			sourceManager.getSourceMapEntryIterator(ret2_1.getAddress(), false);
		assertTrue(iter.hasNext());
		assertEquals(entry1, iter.next());
		assertFalse(iter.hasNext());
		iter.next();
	}

	@Test
	public void testForwardIterator() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding first source map entry");
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		SourceMapEntry entry3 = null;
		SourceMapEntry entry4 = null;
		SourceMapEntry entry5 = null;

		SourceMapEntryIterator iter =
			sourceManager.getSourceMapEntryIterator(ret2_1.getAddress(), true);
		for (int i = 0; i < 10; i++) {
			assertFalse(iter.hasNext());
		}

		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
			entry2 = sourceManager.addSourceMapEntry(source1, 2, ret2_1.getAddress(), 2);
			entry3 = sourceManager.addSourceMapEntry(source2, 3, ret2_1.getAddress().add(1), 0);
			entry4 = sourceManager.addSourceMapEntry(source3, 4, nop1_1.getAddress(), 1);
			entry5 = sourceManager.addSourceMapEntry(source3, 5, nop1_1.getAddress(), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
		Set<SourceMapEntry> entries = new HashSet<>();
		iter = sourceManager.getSourceMapEntryIterator(ret2_1.getAddress(), true);

		for (int i = 0; i < 10; i++) {
			assertTrue(iter.hasNext());
		}
		entries.add(iter.next());

		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry2));

		entries.clear();

		assertTrue(iter.hasNext());
		assertEquals(entry3, iter.next());

		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry4));
		assertTrue(entries.contains(entry5));
		assertFalse(iter.hasNext());
		entries.clear();

		iter = sourceManager.getSourceMapEntryIterator(ret2_1.getAddress().add(1), true);
		assertTrue(iter.hasNext());
		assertEquals(entry3, iter.next());

		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry4));
		assertTrue(entries.contains(entry5));
		assertFalse(iter.hasNext());

		iter = sourceManager.getSourceMapEntryIterator(ret2_2.getAddress(), true);
		assertFalse(iter.hasNext());
	}

	@Test
	public void testBackwardIterator() throws AddressOverflowException, LockException {
		int txId = program.startTransaction("adding first source map entry");
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		SourceMapEntry entry3 = null;
		SourceMapEntry entry4 = null;
		SourceMapEntry entry5 = null;

		SourceMapEntryIterator iter =
			sourceManager.getSourceMapEntryIterator(ret2_1.getAddress(), false);
		for (int i = 0; i < 10; i++) {
			assertFalse(iter.hasNext());
		}

		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, ret2_1.getAddress(), 2);
			entry2 = sourceManager.addSourceMapEntry(source1, 2, ret2_1.getAddress(), 2);
			entry3 = sourceManager.addSourceMapEntry(source2, 3, ret2_1.getAddress().add(1), 0);
			entry4 = sourceManager.addSourceMapEntry(source3, 4, nop1_1.getAddress(), 1);
			entry5 = sourceManager.addSourceMapEntry(source3, 5, nop1_1.getAddress(), 1);
		}
		finally {
			program.endTransaction(txId, true);
		}
		Set<SourceMapEntry> entries = new HashSet<>();
		iter = sourceManager.getSourceMapEntryIterator(nop1_1.getAddress(), false);

		for (int i = 0; i < 10; i++) {
			assertTrue(iter.hasNext());
		}
		entries.add(iter.next());
		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry4));
		assertTrue(entries.contains(entry5));

		entries.clear();

		assertTrue(iter.hasNext());
		assertEquals(entry3, iter.next());

		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry1));
		assertFalse(iter.hasNext());
		entries.clear();

		iter = sourceManager.getSourceMapEntryIterator(ret2_1.getAddress().add(1), false);
		assertTrue(iter.hasNext());
		assertEquals(entry3, iter.next());

		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(iter.hasNext());
		entries.add(iter.next());
		assertTrue(entries.contains(entry1));
		assertTrue(entries.contains(entry2));
		assertFalse(iter.hasNext());

	}

}
