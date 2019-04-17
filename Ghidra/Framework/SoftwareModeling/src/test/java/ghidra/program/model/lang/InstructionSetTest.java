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
package ghidra.program.model.lang;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionError.InstructionErrorType;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class InstructionSetTest extends AbstractGenericTest {

	private InstructionSet instructionSet;

	public InstructionSetTest() {
		super();
	}

	private Address addr(long offset) {
		return AddressSpace.DEFAULT_REGISTER_SPACE.getAddress(offset);
	}

	@Before
	public void setUp() throws Exception {
		// create a block graph as follows: 
		//
		//   ----- 
		//  | b00 |
		//   ----- 
		//     |
		//     |
		//     |         -----         
		//     |        | b10 |<-----
		//     |         -----       |
		//     |           |         |
		//     |           |         |
		//     |         -----       |        
		//      ------->| b20 |      |
		//     |         -----       |
		//     |           |         |
		//     |           |         |
		//     |         -----       |  
		//     |        | b30 |------
		//     |         -----    
		//     |           |  \
		//     |           |   \
		//     |         -----  \        -----
		//      ------->| b40 |   ----->| b50 |
		//               -----           -----
		//
		//   ----- 		 -----
		//  | b70 |---->| b60 |
		//   ----- 		 -----
		//

		InstructionBlock b00 = createBlock(addr(0x00), 5);
		InstructionBlock b10 = createBlock(addr(0x10), 5);
		InstructionBlock b20 = createBlock(addr(0x20), 5);
		InstructionBlock b30 = createBlock(addr(0x30), 5);
		InstructionBlock b40 = createBlock(addr(0x40), 5);
		InstructionBlock b50 = createBlock(addr(0x50), 5);
		InstructionBlock b60 = createBlock(addr(0x60), 5);
		InstructionBlock b70 = createBlock(addr(0x70), 5);

		b00.addBranchFlow(b20.getStartAddress());
		b00.addBranchFlow(b40.getStartAddress());

		b10.setFlowFromAddress(b30.getLastInstructionAddress());
		b10.setFallThrough(b20.getStartAddress());

		b20.setFlowFromAddress(b00.getLastInstructionAddress());
		b20.setFallThrough(b30.getStartAddress());

		b30.setFlowFromAddress(b20.getLastInstructionAddress());
		b30.setFallThrough(b40.getStartAddress());
		b30.addBranchFlow(b10.getStartAddress());
		b30.addBranchFlow(b50.getStartAddress());

		b40.setFlowFromAddress(b30.getLastInstructionAddress());

		b50.setFlowFromAddress(b30.getLastInstructionAddress());

		b70.addBranchFlow(b60.getStartAddress());

		b60.setFlowFromAddress(b70.getLastInstructionAddress());

		// Order of blocks added must follow flow
		instructionSet = new InstructionSet(null);
		instructionSet.addBlock(b00);
		instructionSet.addBlock(b20);
		instructionSet.addBlock(b30);
		instructionSet.addBlock(b40);
		instructionSet.addBlock(b10);
		instructionSet.addBlock(b50);
		instructionSet.addBlock(b70);
		instructionSet.addBlock(b60);
	}

	private InstructionBlock createBlock(Address start, int length) {
		InstructionPrototype proto = new InvalidPrototype(null);
		MemBuffer buf = new ByteMemBufferImpl(start, new byte[100], true);

		try {
			InstructionBlock block = new InstructionBlock(start);
			for (int i = 0; i < length; i++) {
				Address addr = start.add(i);
				PseudoInstruction instr = new PseudoInstruction(addr, proto, buf, null);
				block.addInstruction(instr);
			}
			return block;
		}
		catch (AddressOverflowException e) {
			Assert.fail("unexpected");
		}
		return null;
	}

	@Test
	public void testBasicIterator() {
		Iterator<InstructionBlock> it = instructionSet.iterator();

		assertTrue(it.hasNext());
		InstructionBlock next = it.next();
		Assert.assertEquals(addr(0), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x20), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x30), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x40), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x10), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x50), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x70), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x60), next.getStartAddress());

		assertFalse(it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void testBlock30HasConflict() {
		Iterator<InstructionBlock> it = instructionSet.iterator();

		assertTrue(it.hasNext());
		InstructionBlock next = it.next();
		Assert.assertEquals(addr(00), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x20), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x30), next.getStartAddress());
		next.setInstructionError(InstructionErrorType.INSTRUCTION_CONFLICT, addr(0x33), addr(0x34),
			null, "Test conflict");

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x40), next.getStartAddress());

		assertTrue(it.hasNext());
		next = it.next();
		Assert.assertEquals(addr(0x70), next.getStartAddress());
		next.setInstructionError(InstructionErrorType.INSTRUCTION_CONFLICT, addr(0x73), addr(0x74),
			null, "Test conflict");

		assertFalse(it.hasNext());
		assertNull(it.next());

	}

	@Test
	public void testAddressSet() {
		AddressSet results = new AddressSet();
		results.addRange(addr(0), addr(4));
		results.addRange(addr(0x10), addr(0x14));
		results.addRange(addr(0x20), addr(0x24));
		results.addRange(addr(0x30), addr(0x34));
		results.addRange(addr(0x40), addr(0x44));
		results.addRange(addr(0x50), addr(0x54));
		results.addRange(addr(0x60), addr(0x64));
		results.addRange(addr(0x70), addr(0x74));

		Assert.assertEquals(results, instructionSet.getAddressSet());
	}

	@Test
	public void testInstructionCount() {
		Assert.assertEquals(40, instructionSet.getInstructionCount());
	}
}
