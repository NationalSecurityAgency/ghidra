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

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.task.TaskMonitorAdapter;

public class AddressMapDB64BitTest extends AbstractAddressMapDBTestClass {

	private static final LanguageID LANGUAGE_64BIT = new LanguageID("sparc:BE:64:default");

	/**
	 * Constructor for AddressMapTest.
	 * @param arg0
	 */
	public AddressMapDB64BitTest() {
		super();
	}

	@Override
	protected Program createTestProgram() throws Exception {
		Program p = createProgram(LANGUAGE_64BIT);
		boolean success = false;
		int txId = p.startTransaction("Define blocks");
		try {
			AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
			p.setImageBase(space.getAddress(0x1000000000L), true);
			Memory mem = p.getMemory();

			// Block1 is located within first chunk following image base (base #0 allocated)			
			mem.createUninitializedBlock("Block1", space.getAddress(0x2000000000L), 0x100000,
				false);

			try {
				mem.createUninitializedBlock("Block2", space.getAddress(0xfffffd000L), 0x4000,
					false);
				Assert.fail("Expected MemoryConflictException");
			}
			catch (MemoryConflictException e) {
				// Expected
			}

			try {
				mem.createUninitializedBlock("Block2", space.getAddress(0xfffffffffff00000L),
					0x100001, false);
				Assert.fail("Expected AddressOverflowException");
			}
			catch (AddressOverflowException e) {
				// Expected
			}

			// Block2 is at absolute end of space (base #1 allocated)
			mem.createUninitializedBlock("Block2", space.getAddress(0xfffffffffff00000L), 0x100000,
				false);

			// Block3 spans two (2) memory chunks and spans transition between positive and negative offset values
			// (base #2(end of block) and #3(start of block) allocated
			mem.createInitializedBlock("Block3", space.getAddress(0x7ffffffffff00000L), 0x200000,
				(byte) 0, TaskMonitorAdapter.DUMMY_MONITOR, false);

			success = true;
		}
		finally {
			p.endTransaction(txId, true);
			if (!success) {
				p.release(this);
			}
		}
		return p;
	}

	@Test
	public void testKeyRanges() {

		List<KeyRange> keyRanges = addrMap.getKeyRanges(addr(0), addr(0xffffffffffffffffL), false);

		assertEquals(4, keyRanges.size());

		KeyRange kr = keyRanges.get(0);
		System.out.println(
			addrMap.decodeAddress(kr.minKey) + "->" + addrMap.decodeAddress(kr.maxKey));
		assertEquals(addr(0x2000000000L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x20ffffffffL), addrMap.decodeAddress(kr.maxKey));
		kr = keyRanges.get(1);
		System.out.println(
			addrMap.decodeAddress(kr.minKey) + "->" + addrMap.decodeAddress(kr.maxKey));
		assertEquals(addr(0x7fffffff00000000L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x7fffffffffffffffL), addrMap.decodeAddress(kr.maxKey));
		kr = keyRanges.get(2);
		System.out.println(
			addrMap.decodeAddress(kr.minKey) + "->" + addrMap.decodeAddress(kr.maxKey));
		assertEquals(addr(0x8000000000000000L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x80000000ffffffffL), addrMap.decodeAddress(kr.maxKey));
		kr = keyRanges.get(3);
		System.out.println(
			addrMap.decodeAddress(kr.minKey) + "->" + addrMap.decodeAddress(kr.maxKey));
		assertEquals(addr(0x0ffffffff00000000L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x0ffffffffffffffffL), addrMap.decodeAddress(kr.maxKey));

	}

	@Test
	public void testRelocatableAddress() {

		Address addr = addr(0x1000000000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, addrMap.getKey(addr, false));

		int txId = program.startTransaction("New address region");
		try {
			// base #5 allocated
			long key = addrMap.getKey(addr, true);
			assertEquals(0x2000000400000000L, key);
			assertEquals(addr, addrMap.decodeAddress(key));
		}
		finally {
			program.endTransaction(txId, true);
		}

		addr = addr(0x2000001000L);
		long key = addrMap.getKey(addr, false);
		assertEquals(0x2000000000000000L + 0x1000, key);
		assertEquals(addr, addrMap.decodeAddress(key));

		addr = addr(0x7ffffffffff00000L);
		key = addrMap.getKey(addr, false);
		assertEquals(0x2000000200000000L + 0x0fff00000L, key);
		assertEquals(addr, addrMap.decodeAddress(key));

		addr = addr(0x8ffffffffff00000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, addrMap.getKey(addr, false));

		txId = program.startTransaction("New address region");
		try {
			key = addrMap.getKey(addr, true);
			assertEquals(0x2000000500000000L + 0x0fff00000L, key);
			assertEquals(addr, addrMap.decodeAddress(key));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testAbsoluteAddress() {

		Address addr = addr(0x1000000000L);
		long key = addrMap.getAbsoluteEncoding(addr, false);
		assertEquals(0x1000000000000000L, key);
		assertEquals(addr, addrMap.decodeAddress(key));

		addr = addr(0x2000001000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, addrMap.getAbsoluteEncoding(addr, false));

		int txId = program.startTransaction("New address region");
		try {
			key = addrMap.getAbsoluteEncoding(addr, true);
			assertEquals(0x1000000400000000L + 0x1000, key);
			assertEquals(addr, addrMap.decodeAddress(key));
		}
		finally {
			program.endTransaction(txId, true);
		}

		addr = addr(0x7fffffeffff00000L);
		key = addrMap.getAbsoluteEncoding(addr, false);
		assertEquals(0x1000000200000000L + 0x0fff00000L, key);
		assertEquals(addr, addrMap.decodeAddress(key));

		addr = addr(0x8ffffffffff00000L);
		assertEquals(AddressMap.INVALID_ADDRESS_KEY, addrMap.getAbsoluteEncoding(addr, false));

		txId = program.startTransaction("New address region");
		try {
			key = addrMap.getAbsoluteEncoding(addr, true);
			assertEquals(0x1000000500000000L + 0x0fff00000L, key);
			assertEquals(addr, addrMap.decodeAddress(key));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

}
