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

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.test.TestProcessorConstants;

public class AddressMapDB16BitTest extends AbstractAddressMapDBTestClass {
	
	/**
	 * Constructor for AddressMapTest.
	 * @param arg0
	 */
	public AddressMapDB16BitTest() {
		super();
	}
	
	@Override
    protected Program createTestProgram() throws Exception {
		Program p = createProgram(TestProcessorConstants.PROCESSOR_8051);
		boolean success = false;
		int txId = p.startTransaction("Define blocks");
		try {
			AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();
			p.setImageBase(space.getAddress(0x1000), true);
			Memory mem = p.getMemory();
			
			// Block1 is located within first chunk following image base
			mem.createUninitializedBlock("Block1", space.getAddress(0x2000), 0x1000, false);
			
			try {
				mem.createUninitializedBlock("Block2", space.getAddress(0x200), 0x1000, false);
				Assert.fail("Expected MemoryConflictException");
			}
			catch (MemoryConflictException e) {
				// Expected
			}
			
			try {
				space.getAddress(0x10000);
				Assert.fail("Expected AddressOutOfBoundsException");
			}
			catch (AddressOutOfBoundsException e) {
				// Expected
			}
			
			try {
				mem.createUninitializedBlock("Block2", space.getAddress(0xf000), 0x1001, false);
				Assert.fail("Expected AddressOverflowException");
			}
			catch (AddressOverflowException e) {
				// Expected
			}
			
			// Block2 is at absolute end of space
			mem.createUninitializedBlock("Block2", space.getAddress(0xf000), 0x1000, false);
			
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

		assertEquals(2, keyRanges.size()); // split due to image base

		KeyRange kr = keyRanges.get(0);
		assertEquals(addr(0x0L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x0fffL), addrMap.decodeAddress(kr.maxKey));
		kr = keyRanges.get(1);
		assertEquals(addr(0x1000L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x0ffffL), addrMap.decodeAddress(kr.maxKey));
		
		try {
			program.setImageBase(addr(0), false);
		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail(e.toString());
		}
		
		keyRanges = addrMap.getKeyRanges(addr(0), addr(0xffffffffffffffffL), false);

		assertEquals(1, keyRanges.size());

		kr = keyRanges.get(0);
		assertEquals(addr(0x0L), addrMap.decodeAddress(kr.minKey));
		assertEquals(addr(0x0ffffL), addrMap.decodeAddress(kr.maxKey));

	}
	
@Test
    public void testRelocatableAddress() {
		Address addr = addr(0x1000);
		long key = addrMap.getKey(addr, false);
		assertEquals(0x2000000000000000L + 0x0, key);
		assertEquals(addr, addrMap.decodeAddress(key));
		
		addr = addr(0x1200);
		key = addrMap.getKey(addr, false);
		assertEquals(0x2000000000000000L + 0x200, key);
		assertEquals(addr, addrMap.decodeAddress(key));
	}
	
@Test
    public void testAbsoluteAddress() {
		Address addr = addr(0x1000);
		long key = addrMap.getAbsoluteEncoding(addr, false);
		assertEquals(0x1000000000000000L + 0x1000, key);
		assertEquals(addr, addrMap.decodeAddress(key));
		
		addr = addr(0x1200);
		key = addrMap.getAbsoluteEncoding(addr, false);
		assertEquals(0x1000000000000000L + 0x1200, key);
		assertEquals(addr, addrMap.decodeAddress(key));
	}
	
}
