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
package ghidra.program.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * quick and dirty test of the ProgramContextImpl just to see
 * if the values are being set for specified address range.
 * The ProgramContextPlugin will be a more complete test
 * program, with a gui interface to specify the values and
 * select/highlight an address range.
 */
public class ConstantPropogationReferenceTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;
	private int txID;

	private ConstantPropagationAnalyzer analyzer;

	public ConstantPropogationReferenceTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("MIPS_6432", "MIPS:BE:64:64-32addr");
		// lui v0, 0x80a8
		// addiu v0, v0, -0xdf0
		// sw    v0, -0x46e8(gp)
		builder.setBytes("0x80a7f210",
			"00,00,00,00,3c,02,80,a8,24,42,f2,10,af,82,b9,18,01,01,01,01");

		builder.disassemble("0x80a7f214", 12);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		txID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(txID, true);
	}

	@Test
    public void testOperandRef_MIPS6432() throws Exception {

		Address codeStart = addr("0x80a7f214");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(12));
		analyze(addressSet);

		Instruction instr = listing.getInstructionAt(addr("0x80a7f21c"));
		assertOperandReferenceTo(0, instr, addr("0x80a7f210"));
		assertNoOperandReference(1, instr);

		setRegister(codeStart, 0x90000000L);

		analyze(addressSet);

		assertOperandReferenceTo(1, instr, addr("0x8fffb918"));
	}

	private void assertNoOperandReference(int opIndex, Instruction instr) {
		Reference[] refs = instr.getOperandReferences(1);
		assertEquals("No reference on operand " + opIndex, 0, refs.length);
	}

	private void assertOperandReferenceTo(int opIndex, Instruction instr, Address to) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("Operand " + opIndex + " num refs", 1, refs.length);
		assertEquals("Operand " + opIndex + " Ref Check", to, refs[0].getToAddress());
	}

	private void analyze(AddressSet addrs) throws Exception {
		analyzer.added(program, addrs, TaskMonitor.DUMMY, null);
	}

	private void setRegister(Address a, long value) throws Exception {
		ProgramContext context = program.getProgramContext();
		Register gp = context.getRegister("gp");
		context.setRegisterValue(a, a.add(12), new RegisterValue(gp, BigInteger.valueOf(value)));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
