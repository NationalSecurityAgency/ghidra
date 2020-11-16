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
package ghidra.app.cmd.disassemble;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.ProgramContextImpl;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Test for the {@link ghidra.app.cmd.label.CreateNamespacesCmd} class.
 * 
 * 
 * @since  Tracker Id 619
 */
public class DisassembleContextTest extends AbstractGhidraHeadedIntegrationTest {

	private static final BigInteger ZERO = BigInteger.valueOf(0);
	private static final BigInteger ONE = BigInteger.valueOf(1);
	private static final BigInteger VAL1 = BigInteger.valueOf(-20);

	private Program program;
	private AddressSpace space;
	private Register tmodeReg;
	private Register r0Reg;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._ARM, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		tmodeReg = program.getRegister("TMode");
		r0Reg = program.getRegister("r0");

		program.startTransaction("TEST");
		program.getMemory().createUninitializedBlock("testBlock", space.getAddress(0), 0x100,
			false);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
		}
	}

//	public void testFlowWithSaveIntoProgramContext() {
//
//		// Program context contains default value of 0 for TMode context register bit
//		ProgramContext retainedContext = program.getProgramContext();
//
//		Address addr = space.getAddress(0x0);
//
//		// context register changes WILL be saved into program context
//		// CHANGED! Context saved when instruction created by CodeManager only
//		DisassemblerContextImpl context = new DisassemblerContextImpl(retainedContext);
//		context.flowStart(addr);
//
//		context.setValue(tmodeReg, ZERO);
//
//		for (int i = 0; i < 20; i++) {
//			addr = addr.next();
//			context.flowToAddress(addr);
//		}
//
//		assertEquals(ZERO, context.getValue(tmodeReg, addr.previous(), false));
//
//		// should catch that addr is currentAddr
//		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
//		assertEquals(ZERO, context.getValue(tmodeReg, false));
//		assertNull(context.getValue(r0Reg, addr, true));
//		assertNull(context.getValue(r0Reg, true));
//
//		// explicit set of future value before flow-to
//		addr = addr.add(30);
//		context.setValue(tmodeReg, addr, ONE);
//		context.setValue(r0Reg, VAL1);
//
//		// Flow-to set-point and check it out
//		context.flowToAddress(addr);
//
//		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr.previous(), false));
//		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr.previous(), true));
//
//		// original default value still present in program context
//		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));
//		assertNull(retainedContext.getValue(r0Reg, addr, true));
//
//		// current disassembler context - not yet stored to program context
//		assertEquals(ONE, context.getValue(tmodeReg, false));
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(VAL1, context.getValue(r0Reg, true));
//		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
//
//		// default context returned from address we have not yet flowed-to
//		addr = addr.next();
//		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
//		assertNull(context.getValue(r0Reg, addr, true));
//
//		// Indicate future flow - context should be copied
//		Address futureFlowAddr = addr.add(50);
//		context.copyToFutureFlowState(futureFlowAddr);
//
//		// End flow causes current context to be written
//		context.flowEnd(addr);
//
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(ONE, retainedContext.getValue(tmodeReg, addr, false));
//		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
//		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr, true));
//
//		// Restart flow at futureFlowAddr
//		context.flowStart(futureFlowAddr);
//		addr = futureFlowAddr;
//
//		// original default value still present in program context
//		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));
//		assertNull(retainedContext.getValue(r0Reg, addr, true));
//
//		// current disassembler context - not yet stored to program context
//		assertEquals(ONE, context.getValue(tmodeReg, false));
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(VAL1, context.getValue(r0Reg, true));
//		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
//
//		// default context returned from address we have not yet flowed-to
//		addr = addr.next();
//		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
//		assertNull(context.getValue(r0Reg, addr, true));
//
//		// End flow causes current context to be written
//		context.flowEnd(addr);
//
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(ONE, retainedContext.getValue(tmodeReg, addr, false));
//		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
//		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr, true));
//	}

	@Test
    public void testFlowWithNoSaveIntoProgramContext() {

		// Program context contains default value of 0 for TMode context register bit
		ProgramContext retainedContext = program.getProgramContext();

		Address addr = space.getAddress(0x0);

		// context register changes WILL NOT be saved into program context
		DisassemblerContextImpl context = new DisassemblerContextImpl(retainedContext);
		context.flowStart(addr);

		context.setValue(tmodeReg, ZERO);

		for (int i = 0; i < 20; i++) {
			addr = addr.next();
			context.flowToAddress(addr);
		}

		assertEquals(ZERO, context.getValue(tmodeReg, addr.previous(), false));

		// should catch that addr is currentAddr
		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
		assertEquals(ZERO, context.getValue(tmodeReg, false));
		assertNull(context.getValue(r0Reg, addr, true));
		assertNull(context.getValue(r0Reg, true));

		// explicit set of future value before flow-to
		addr = addr.add(30);
		context.setValue(tmodeReg, addr, ONE);
		context.setValue(r0Reg, VAL1);

		// Flow-to set-point and check it out
		context.flowToAddress(addr);

		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr.previous(), false));
		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr.previous(), true));

		// original default value still present in program context
		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));
		assertNull(retainedContext.getValue(r0Reg, addr, true));

		// current disassembler context - not yet stored to program context
		assertEquals(ONE, context.getValue(tmodeReg, false));
		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
		assertEquals(VAL1, context.getValue(r0Reg, true));
		assertEquals(VAL1, context.getValue(r0Reg, addr, true));

		// default context returned from address we have not yet flowed-to
		addr = addr.next();
		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
		assertNull(context.getValue(r0Reg, addr, true));

		// Indicate future flow - context should be copied
		Address futureFlowAddr = addr.add(50);
		context.copyToFutureFlowState(futureFlowAddr);

		// End flow causes current context to be written
		context.flowEnd(addr);

		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr, true));

		// default value still intact
		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));

		// Restart flow at futureFlowAddr
		context.flowStart(futureFlowAddr);
		addr = futureFlowAddr;

		// original default value still present in program context
		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));
		assertNull(retainedContext.getValue(r0Reg, addr, true));

		// current disassembler context - not yet stored to program context
		assertEquals(ONE, context.getValue(tmodeReg, false));
		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
		assertEquals(VAL1, context.getValue(r0Reg, true));
		assertEquals(VAL1, context.getValue(r0Reg, addr, true));

		// default context returned from address we have not yet flowed-to
		addr = addr.next();
		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
		assertNull(context.getValue(r0Reg, addr, true));

		// End flow causes current context to be written
		context.flowEnd(addr);

		assertEquals(VAL1, context.getValue(r0Reg, addr, true));
		assertEquals(VAL1, retainedContext.getValue(r0Reg, addr, true));

		// default value still intact
		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr, false));
	}

//	public void testFlowWithSaveIntoContextImpl() {
//
//		// Simple context does not contain default values
//		ProgramContext retainedContext =
//			new ProgramContextImpl(program.getLanguage().getRegisters());
//
//		Address addr = space.getAddress(0x0);
//
//		// context register changes WILL be saved into program context
//		// CHANGED! Context saved when instruction created by CodeManager only
//		DisassemblerContextImpl context = new DisassemblerContextImpl(retainedContext);
//		context.flowStart(addr);
//
//		context.setValue(tmodeReg, ZERO);
//
//		for (int i = 0; i < 20; i++) {
//			addr = addr.next();
//			context.flowToAddress(addr);
//		}
//
//		assertEquals(ZERO, context.getValue(tmodeReg, addr.previous(), false));
//
//		// should catch that addr is currentAddr
//		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
//		assertEquals(ZERO, context.getValue(tmodeReg, false));
//
//		// explicit set of future value before flow-to
//		addr = addr.add(30);
//		context.setValue(tmodeReg, addr, ONE);
//
//		// Flow-to set-point and check it out
//		context.flowToAddress(addr);
//
//		assertEquals(ZERO, retainedContext.getValue(tmodeReg, addr.previous(), false));
//
//		// original default value still present in program context
//		assertNull(retainedContext.getValue(tmodeReg, addr, false));
//
//		// current disassembler context - not yet stored to program context
//		assertEquals(ONE, context.getValue(tmodeReg, false));
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//
//		// default context returned from address we have not yet flowed-to
//		addr = addr.next();
//		assertNull(context.getValue(tmodeReg, addr, false));
//
//		// Indicate future flow - context should be copied
//		Address futureFlowAddr = addr.add(50);
//		context.copyToFutureFlowState(futureFlowAddr);
//
//		// End flow causes current context to be written
//		context.flowEnd(addr);
//
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(ONE, retainedContext.getValue(tmodeReg, addr, false));
//
//		// Restart flow at futureFlowAddr
//		context.flowStart(futureFlowAddr);
//		addr = futureFlowAddr;
//
//		// original default value still present in program context
//		assertNull(retainedContext.getValue(tmodeReg, addr, false));
//
//		// current disassembler context - not yet stored to program context
//		assertEquals(ONE, context.getValue(tmodeReg, false));
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//
//		// default context returned from address we have not yet flowed-to
//		addr = addr.next();
//		assertNull(context.getValue(tmodeReg, addr, false));
//
//		// End flow causes current context to be written
//		context.flowEnd(addr);
//
//		assertEquals(ONE, context.getValue(tmodeReg, addr, false));
//		assertEquals(ONE, retainedContext.getValue(tmodeReg, addr, false));
//	}

	@Test
    public void testFlowWithNoSaveIntoContextImpl() {

		// Simple context does not contain default values
		ProgramContext retainedContext = new ProgramContextImpl(program.getLanguage());

		Address addr = space.getAddress(0x0);

		// context register changes WILL NOT be saved into program context
		DisassemblerContextImpl context = new DisassemblerContextImpl(retainedContext);
		context.flowStart(addr);

		context.setValue(tmodeReg, ZERO);

		for (int i = 0; i < 20; i++) {
			addr = addr.next();
			context.flowToAddress(addr);
		}

		assertEquals(ZERO, context.getValue(tmodeReg, addr.previous(), false));

		// should catch that addr is currentAddr
		assertEquals(ZERO, context.getValue(tmodeReg, addr, false));
		assertEquals(ZERO, context.getValue(tmodeReg, false));

		// explicit set of future value before flow-to
		addr = addr.add(30);
		context.setValue(tmodeReg, addr, ONE);

		// Flow-to set-point and check it out
		context.flowToAddress(addr);

		assertNull(retainedContext.getValue(tmodeReg, addr.previous(), false));

		// original default value still present in program context
		assertNull(retainedContext.getValue(tmodeReg, addr, false));

		// current disassembler context - not yet stored to program context
		assertEquals(ONE, context.getValue(tmodeReg, false));
		assertEquals(ONE, context.getValue(tmodeReg, addr, false));

		// default context returned from address we have not yet flowed-to
		addr = addr.next();
		assertNull(context.getValue(tmodeReg, addr, false));

		// Indicate future flow - context should be copied
		Address futureFlowAddr = addr.add(50);
		context.copyToFutureFlowState(futureFlowAddr);

		// End flow causes current context to be written
		context.flowEnd(addr);

		// default value still intact
		assertNull(retainedContext.getValue(tmodeReg, addr, false));

		// Restart flow at futureFlowAddr
		context.flowStart(futureFlowAddr);
		addr = futureFlowAddr;

		// original default value still present in program context
		assertNull(retainedContext.getValue(tmodeReg, addr, false));

		// current disassembler context - not yet stored to program context
		assertEquals(ONE, context.getValue(tmodeReg, false));
		assertEquals(ONE, context.getValue(tmodeReg, addr, false));

		// default context returned from address we have not yet flowed-to
		addr = addr.next();
		assertNull(context.getValue(tmodeReg, addr, false));

		// End flow causes current context to be written
		context.flowEnd(addr);

		// default value still intact
		assertNull(retainedContext.getValue(tmodeReg, addr, false));
	}
}
