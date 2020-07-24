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
package ghidra.util.state;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.util.ProgramContextImpl;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class ContextStateTest extends AbstractGhidraHeadedIntegrationTest {

	private Language lang;
	private Program program;
	private AddressFactory addrFactory;

	private Varnode regEAX;
	private Varnode regAX;
	private Varnode regAH;
	private Varnode regAL;
	private Varnode regEBX;
	private Varnode regBX;

	private Varnode mem4;
	private Varnode mem3;
	private Varnode mem2;
	private Varnode mem1;

	public ContextStateTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		lang = getSLEIGH_X86_LANGUAGE();
		program = createDefaultProgram("Test", ProgramBuilder._X86, this);
		addrFactory = program.getAddressFactory();
		Register reg = lang.getRegister("EAX");
		regEAX = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		reg = lang.getRegister("AX");
		regAX = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		reg = lang.getRegister("AH");
		regAH = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		reg = lang.getRegister("AL");
		regAL = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		reg = lang.getRegister("EBX");
		regEBX = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		reg = lang.getRegister("BX");
		regBX = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		mem4 = new Varnode(addr(100), 4);
		mem3 = new Varnode(addr(100), 3);
		mem2 = new Varnode(addr(100), 2);
		mem1 = new Varnode(addr(100), 1);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
		}
	}

	private Address addr(long offset) {
		return addrFactory.getDefaultAddressSpace().getAddress(offset);
	}

	@Test
	public void testStoreConstant() {

		ContextState state1 = new ContextState(addr(1000), program);
		state1.store(regEAX, new Varnode(addrFactory.getConstantAddress(0x12345678), 4));
		state1.store(mem4, new Varnode(addrFactory.getConstantAddress(0x98765432), 4));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x12345678), 4),
			state1.get(regEAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x5678), 2), state1.get(regAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x56), 1), state1.get(regAH));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x78), 1), state1.get(regAL));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x98765432L), 4), state1.get(mem4));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x765432), 3), state1.get(mem3));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x5432), 2), state1.get(mem2));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x32), 1), state1.get(mem1));
	}

	@Test
	public void testStoreConstant2() {

		ContextState state1 = new ContextState(addr(1000), program);
		state1.store(regEAX, new Varnode(addrFactory.getConstantAddress(0x12345678), 4));
		state1.store(mem4, new Varnode(addrFactory.getConstantAddress(0x98765432), 4));

		ContextState state2 = state1.branchState(new SequenceNumber(addr(1001), 0));
		state2.store(regAX, new Varnode(addrFactory.getConstantAddress(0x9955), 2));
		state1.store(new Varnode(addr(101), 2),
			new Varnode(addrFactory.getConstantAddress(0x1133), 2));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x12349955), 4),
			state2.get(regEAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x9955), 2), state2.get(regAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x99), 1), state2.get(regAH));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x55), 1), state2.get(regAL));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x98113332L), 4), state1.get(mem4));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x113332), 3), state1.get(mem3));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x3332), 2), state1.get(mem2));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x32), 1), state1.get(mem1));
	}

	@Test
	public void testStoreConstantWithEntryContext() {

		ProgramContextImpl ctx = new ProgramContextImpl(lang);
		ctx.setDefaultValue(
			new RegisterValue(lang.getRegister("EAX"), new BigInteger("fedcba98", 16)), addr(1000),
			addr(1000));

		ContextState state1 = new ContextState(addr(1000), ctx, program);
		state1.store(regAX, new Varnode(addrFactory.getConstantAddress(0x1234), 2));

		Varnode v = new Varnode(addrFactory.getConstantAddress(0xfedc1234), 4);
		v.trim();
		assertEquals(v, state1.get(regEAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x1234), 2), state1.get(regAX));
	}

	@Test
	public void testStoreExpression() {

		ContextState state1 = new ContextState(addr(1000), program);

		PcodeOp zextEAX = new PcodeOp(addr(1000), 0, PcodeOp.INT_ZEXT,
			new Varnode[] { regBX, new Varnode(addrFactory.getConstantAddress(4), 4) }, regEAX);
		VarnodeOperation zextEAXop = new VarnodeOperation(zextEAX, zextEAX.getInputs());
		state1.store(regEAX, zextEAXop);

		PcodeOp addEAX2 = new PcodeOp(addr(1000), 0, PcodeOp.INT_ADD,
			new Varnode[] { regEAX, new Varnode(addrFactory.getConstantAddress(2), 4) }, mem4);
		VarnodeOperation addEAX2op = new VarnodeOperation(addEAX2, addEAX2.getInputs());
		state1.store(mem4, addEAX2op);

		assertTrue("Failed to reconstitute expression", state1.get(regEAX) == zextEAXop);

		assertEquals(regBX, state1.get(regAX));

		assertTrue("Failed to reconstitute expression", state1.get(mem4) == addEAX2op);

		Varnode v = state1.get(mem1);
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		VarnodeOperation op = (VarnodeOperation) v;
		assertEquals(1, op.getSize());
		assertEquals(PcodeOp.SUBPIECE, op.getPCodeOp().getOpcode());
		assertTrue("Bad byte expression input", addEAX2op == op.getInputValues()[0]);
		assertEquals(new Varnode(addrFactory.getConstantAddress(1), 1), op.getInputValues()[1]);

		v = state1.get(mem2);
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		op = (VarnodeOperation) v;
		assertEquals(2, op.getSize());
		assertEquals(PcodeOp.SUBPIECE, op.getPCodeOp().getOpcode());
		assertTrue("Bad byte expression input", addEAX2op == op.getInputValues()[0]);
		assertEquals(new Varnode(addrFactory.getConstantAddress(2), 1), op.getInputValues()[1]);

		v = state1.get(mem3);
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		op = (VarnodeOperation) v;
		assertEquals(3, op.getSize());
		assertEquals(PcodeOp.SUBPIECE, op.getPCodeOp().getOpcode());
		assertTrue("Bad byte expression input", addEAX2op == op.getInputValues()[0]);
		assertEquals(new Varnode(addrFactory.getConstantAddress(3), 1), op.getInputValues()[1]);

		// Check offcut get (addEAX2op >> 16)[2]
		v = state1.get(new Varnode(addr(102), 2));
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		op = (VarnodeOperation) v;
		assertEquals(2, op.getSize());
		assertEquals(PcodeOp.SUBPIECE, op.getPCodeOp().getOpcode());
		assertEquals(new Varnode(addrFactory.getConstantAddress(2), 1), op.getInputValues()[1]);

		v = op.getInputValues()[0];
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		op = (VarnodeOperation) v;
		assertEquals(4, op.getSize());
		assertEquals(PcodeOp.INT_AND, op.getPCodeOp().getOpcode());
		assertTrue("Bad byte expression input", addEAX2op == op.getInputValues()[0]);
		Varnode mask = new Varnode(addrFactory.getConstantAddress(0xffff0000), addEAX2op.getSize());
		mask.trim();
		assertEquals(mask, op.getInputValues()[1]);
	}

	@Test
	public void testStoreExpression2() {

		ContextState state1 = new ContextState(addr(1000), program);

		PcodeOp zextEAX = new PcodeOp(addr(1000), 0, PcodeOp.INT_ZEXT,
			new Varnode[] { regAX, new Varnode(addrFactory.getConstantAddress(4), 4) }, regEAX);
		VarnodeOperation zextEAXop = new VarnodeOperation(zextEAX, zextEAX.getInputs());
		state1.store(regEAX, zextEAXop);

		ContextState state2 = state1.branchState(new SequenceNumber(addr(1001), 0));
		state2.store(regAX, new Varnode(addrFactory.getConstantAddress(0x9955), 2));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x9955), 2), state2.get(regAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x99), 1), state2.get(regAH));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x55), 1), state2.get(regAL));

		// Special case - simplification recognizes upper word is 0;
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x9955), 4), state2.get(regEAX));
	}

	@Test
	public void testStoreExpression3() {

		ContextState state1 = new ContextState(addr(1000), program);

		PcodeOp addEAX = new PcodeOp(addr(1000), 0, PcodeOp.INT_ADD,
			new Varnode[] { regEAX, new Varnode(addrFactory.getConstantAddress(1), 4) }, regEBX);
		VarnodeOperation addEAXop = new VarnodeOperation(addEAX, addEAX.getInputs());
		state1.store(regEAX, addEAXop);

		ContextState state2 = state1.branchState(new SequenceNumber(addr(1001), 0));
		state2.store(regAX, new Varnode(addrFactory.getConstantAddress(0x9955), 2));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x9955), 2), state2.get(regAX));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x99), 1), state2.get(regAH));
		assertEquals(new Varnode(addrFactory.getConstantAddress(0x55), 1), state2.get(regAL));

		Varnode v = state2.get(regEAX);
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		VarnodeOperation op = (VarnodeOperation) v;
		assertEquals(4, op.getSize());
		assertEquals(PcodeOp.INT_ADD, op.getPCodeOp().getOpcode());

		v = op.getInputValues()[1];
		assertTrue(v.isConstant());
		assertEquals(4, v.getSize());
		assertEquals(0x9955, v.getOffset());

		v = op.getInputValues()[0];
		assertTrue("Expected byte expression", v instanceof VarnodeOperation);
		op = (VarnodeOperation) v;
		assertEquals(4, op.getSize());
		assertEquals(PcodeOp.INT_AND, op.getPCodeOp().getOpcode());
		assertTrue("Bad byte expression input", addEAXop == op.getInputValues()[0]);
		Varnode mask = new Varnode(addrFactory.getConstantAddress(0xffff0000), addEAXop.getSize());
		mask.trim();
		assertEquals(mask, op.getInputValues()[1]);

	}

	@Test
	public void testStoreIntoExpression() {

		ContextState state1 = new ContextState(addr(1000), program);

		PcodeOp addEAX16 = new PcodeOp(addr(1000), 0, PcodeOp.INT_ADD,
			new Varnode[] { regEAX, new Varnode(addrFactory.getConstantAddress(16), 4) }, regEBX);
		VarnodeOperation addEAX16op = new VarnodeOperation(addEAX16, addEAX16.getInputs());

		state1.store(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX16op,
			new Varnode(addrFactory.getConstantAddress(0x12345678), 4), 4);

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x12345678), 4),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX16op, 4));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x345678), 3),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX16op, 3));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x5678), 2),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX16op, 2));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x78), 1),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX16op, 1));

		PcodeOp addEAX18 = new PcodeOp(addr(1000), 0, PcodeOp.INT_ADD,
			new Varnode[] { regEAX, new Varnode(addrFactory.getConstantAddress(18), 4) }, regEBX);
		VarnodeOperation addEAX18op = new VarnodeOperation(addEAX18, addEAX18.getInputs());

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x1234), 2),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX18op, 2));

		assertEquals(new Varnode(addrFactory.getConstantAddress(0x34), 1),
			state1.get(addrFactory.getDefaultAddressSpace().getSpaceID(), addEAX18op, 1));

	}

}
