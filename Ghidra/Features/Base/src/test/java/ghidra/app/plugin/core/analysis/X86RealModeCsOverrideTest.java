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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import java.util.Set;
import java.util.TreeSet;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/**
 * Real-mode x86 code reads CS where a CS: override or a near indirect CALL or JMP needs it. The
 * MZ loader sets CS for each block. Where no loader sets it, the processor spec supplies
 * (address >> 4) & 0xf000, the value these instructions computed before they read CS. Constant
 * propagation treats a segment register holding zero as segment 0, which COM files and code
 * reading the BIOS data area use.
 */
public class X86RealModeCsOverrideTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;
	private int txId;

	@After
	public void tearDown() {
		if (program != null) {
			program.endTransaction(txId, false);
		}
		if (builder != null) {
			builder.dispose();
		}
	}

	private void load(String blockStart, int size, Integer cs) throws Exception {
		load("x86:LE:16:Real Mode", blockStart, size, cs);
	}

	private void load(String language, String blockStart, int size, Integer cs)
			throws Exception {
		builder = new ProgramBuilder("RealModeCs", language);
		program = builder.getProgram();
		txId = program.startTransaction("Test");
		Address start = builder.addr(blockStart);
		builder.createMemory("code", blockStart, size).setExecute(true);
		if (cs != null) {
			builder.setRegisterValue("CS", blockStart, start.add(size - 1).toString(), cs);
		}
	}

	/** Disassembles one instruction at {@code at}, propagates constants through it and
	 * returns the linear addresses it references. */
	private Set<Long> references(String at, String bytes) throws Exception {
		return references(at, bytes, at);
	}

	/** Disassembles {@code bytes} at {@code at} as one function, propagates constants through
	 * it and returns the linear addresses the instruction at {@code from} references. */
	private Set<Long> references(String at, String bytes, String from) throws Exception {
		int length = bytes.split(" ").length;
		builder.setBytes(at, bytes);
		builder.disassemble(at, length);
		builder.createFunction(at);
		Address start = builder.addr(at);
		new ConstantPropagationAnalyzer().added(program,
			new AddressSet(start, start.add(length - 1)), TaskMonitor.DUMMY, null);
		Set<Long> to = new TreeSet<>();
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(builder.addr(from))) {
			to.add(ref.getToAddress().getOffset());
		}
		return to;
	}

	// MOV AX,CS:[0x20]
	private static final String LOAD = "2e a1 20 00";
	// JMP word ptr CS:[0x20]
	private static final String JUMP = "2e ff 26 20 00";

	@Test
	public void testCsOverrideReadsCsFromLoader() throws Exception {
		load("1234:0000", 0x40, 0x1234);
		assertEquals(Set.of(0x12360L), references("1234:0010", LOAD));
	}

	@Test
	public void testJumpTableReadsCsFromLoader() throws Exception {
		load("1234:0000", 0x40, 0x1234);
		builder.setBytes("1234:0020", "30 00");
		// the table entry at 1234:0020 and the target 1234:0030
		assertEquals(Set.of(0x12360L, 0x12370L), references("1234:0000", JUMP));
	}

	@Test
	public void testCsAfterFarCallIsTheCallers() throws Exception {
		load("1234:0000", 0x40, 0x1234);
		builder.createMemory("callee", "2000:0000", 0x10).setExecute(true);
		builder.setBytes("2000:0000", "cb");
		// CALLF 0x2000:0000; MOV AX,CS:[0x20]
		assertEquals(Set.of(0x12360L),
			references("1234:0000", "9a 00 00 00 20 " + LOAD, "1234:0005"));
	}

	@Test
	public void testCsIsNotWritten() throws Exception {
		load("1234:0000", 0x40, 0x1234);
		builder.setBytes("1234:0000", JUMP);
		builder.disassemble("1234:0000", 5);
		Instruction instr = program.getListing().getInstructionAt(builder.addr("1234:0000"));
		Register cs = program.getRegister("CS");
		for (PcodeOp op : instr.getPcode()) {
			Varnode out = op.getOutput();
			assertFalse("CS is written by " + op,
				out != null && out.isRegister() && out.getAddress().equals(cs.getAddress()));
		}
	}

	@Test
	public void testComLayoutWithoutCs() throws Exception {
		load("0000:0000", 0x200, null);
		assertEquals(Set.of(0x20L), references("0000:0100", LOAD));
	}

	@Test
	public void testComLayoutJumpTableWithoutCs() throws Exception {
		load("0000:0000", 0x200, null);
		builder.setBytes("0000:0020", "30 01");
		assertEquals(Set.of(0x20L, 0x130L), references("0000:0100", JUMP));
	}

	@Test
	public void testRomLayoutWithoutCs() throws Exception {
		load("f000:0000", 0x100, null);
		builder.setBytes("f000:0020", "30 00");
		assertEquals(Set.of(0xf0020L, 0xf0030L), references("f000:0000", JUMP));
	}

	@Test
	public void testZeroSegmentRegisterSelectsSegmentZero() throws Exception {
		load("1234:0000", 0x40, 0x1234);
		assertEquals(Set.of(0x46cL), zeroDataSegmentReferences());
	}

	@Test
	public void testZeroSelectorInProtectedModeIsNotReferenced() throws Exception {
		load("x86:LE:16:Protected Mode", "1234:0000", 0x40, null);
		assertEquals(Set.of(), zeroDataSegmentReferences());
	}

	/** References from the last instruction of XOR AX,AX; MOV DS,AX; MOV AX,[0x46c]. */
	private Set<Long> zeroDataSegmentReferences() throws Exception {
		builder.setBytes("1234:0000", "31 c0 8e d8 a1 6c 04");
		builder.disassemble("1234:0000", 7);
		builder.createFunction("1234:0000");
		Address start = builder.addr("1234:0000");
		new ConstantPropagationAnalyzer().added(program, new AddressSet(start, start.add(6)),
			TaskMonitor.DUMMY, null);
		Set<Long> to = new TreeSet<>();
		for (Reference ref : program.getReferenceManager()
				.getReferencesFrom(builder.addr("1234:0004"))) {
			to.add(ref.getToAddress().getOffset());
		}
		return to;
	}

	@Test
	public void testUnalignedSegmentWithoutCsKeepsComputedSegment() throws Exception {
		load("1234:0000", 0x40, null);
		assertEquals(Set.of(0x10020L), references("1234:0010", LOAD));
	}
}
