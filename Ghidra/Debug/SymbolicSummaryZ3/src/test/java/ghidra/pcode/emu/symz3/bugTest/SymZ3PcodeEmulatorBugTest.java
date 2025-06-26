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
package ghidra.pcode.emu.symz3.bugTest;

import static org.junit.Assert.assertEquals;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest;
import ghidra.pcode.emu.symz3.SymZ3PcodeThread;
import ghidra.pcode.emu.symz3.lib.SymZ3EmuUnixFileSystem;
import ghidra.pcode.emu.symz3.lib.SymZ3LinuxAmd64SyscallLibrary;
import ghidra.pcode.emu.symz3.plain.SymZ3PcodeEmulator;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.symz3.model.SymValueZ3;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class SymZ3PcodeEmulatorBugTest extends AbstractGhidraHeadlessIntegrationTest {
	protected final class LinuxAmd64SymZ3PcodeEmulator extends SymZ3PcodeEmulator {
		public LinuxAmd64SymZ3PcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<Pair<byte[], SymValueZ3>> createUseropLibrary() {
			return super.createUseropLibrary()
					.compose(new SymZ3LinuxAmd64SyscallLibrary(this, fs, program));
		}
	}

	protected static final byte[] BYTES_HW = "Hello, World!\n".getBytes();

	private Program program;
	private AddressSpace space;
	private Address start;
	private int size;
	private MemoryBlock block;
	private Assembler asm;

	private SymZ3EmuUnixFileSystem fs;
	private SymZ3PcodeEmulator emulator;

	@Before
	public void setUpSymZ3Test() throws Exception {
		program = createDefaultProgram("HelloSymZ3", "x86:LE:64:default", "gcc", this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (Transaction tid = program.openTransaction("Initialize")) {
			block = program.getMemory()
					.createInitializedBlock(".text", start, size, (byte) 0, TaskMonitor.DUMMY,
						false);

			EmuLinuxAmd64SyscallUseropLibraryTest.SYSCALL_HELPER.bootstrapProgram(program);
		}
		asm = Assemblers.getAssembler(program);
	}

	@After
	public void tearDownSymZ3Test() throws Exception {
		if (program != null) {
			program.release(this);
		}
	}

	public void prepareEmulator() throws Exception {
		// The emulator is not itself bound to the program or a trace, so copy bytes in
		byte[] buf = new byte[size];
		assertEquals(size, block.getBytes(start, buf));
		emulator.getSharedState().getLeft().setVar(space, start.getOffset(), size, true, buf);
	}

	public SymZ3PcodeThread launchThread(Address pc) {
		SymZ3PcodeThread thread = emulator.newThread();
		thread.overrideCounter(start);
		thread.overrideContextWithDefault();
		thread.reInitialize();
		return thread;
	}

	@Test
	// Quick function check, add registers together and verify the output
	public void testAdditionSummary() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"ADD RAX, RCX",
			"ADD RAX, RBX" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		//Execute instructions
		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RAX");

		//Test concrete and symbolic values of RAX
		ImmutablePair<String, String> raxcompare = thread.registerComparison("RAX");
		assertEquals(raxcompare.getLeft(), "0");
		assertEquals(raxcompare.getRight(), "(RAX + RCX + RBX)");
	}

	@Test
	// Simple test to see if memory store/loads of different sizes work
	// Load into [RBP-0x18] as a qword, then make sure we can read it as a dword
	public void testVarSize() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV RAX, 1",
			"MOV qword ptr [RBP + -0x18], RAX",
			"MOV ECX, dword ptr [RBP + -0x18]" };

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		//Execute instructions
		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);

		thread.printRegisterComparison(System.out, "ECX");
		thread.printRegisterComparison(System.out, "RAX");
		ImmutablePair<String, String> raxcompare = thread.registerComparison("RAX");
		assertEquals(raxcompare.getRight(), "(0x1:64)");
		ImmutablePair<String, String> eaxcompare = thread.registerComparison("EAX");
		assertEquals(eaxcompare.getRight(), "(0x1:32)");
		assertEquals(eaxcompare.getLeft(), "1");
	}

	@Test
	// Test to see if zero extend works with differently sized store/loads in the same memory location
	// Load into [RBP-18] as a qword, then make sure we can read the same location with zero extend on a byte
	public void testZeroExtend() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV RAX, 0xdeadbeef",
			"MOV qword ptr [RBP + -0x18], RAX",
			"MOVZX ECX, byte ptr [RBP + -0x18]" };

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		//Execute instructions
		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);

		thread.printRegisterComparison(System.out, "RAX");
		thread.printRegisterComparison(System.out, "ECX");

		//Test that ECX recieves the bottom byte of RAX with zero extend
		ImmutablePair<String, String> raxcompare = thread.registerComparison("RAX");
		ImmutablePair<String, String> ecxcompare = thread.registerComparison("ECX");

		//Test concrete values
		String bottomByte = raxcompare.getLeft().substring(6, 8);
		assertEquals(ecxcompare.getLeft(), bottomByte);
	}

	@Test
	// Test CMOV instruction
	// Using CMOVA (CMOV Above) on RSI and RDI, RDI = 0xdeadbeef and RSI = 0xdeadbeef + 1
	public void testCMOVPass() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV RDI, 0xdeadbeef",
			"CMP RSI, RDI",
			"CMOVA RSI, RDI" };

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		Language language = thread.getLanguage();
		Register regRSI = language.getRegister("RSI");

		//Set RSI to 0xdeadbeef + 1 before executing instructions

		byte[] initRSI = new byte[] { 0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xf, 0x0 };
		thread.getLocalConcreteState().setVar(regRSI, initRSI);

		//Execute instructions
		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);

		thread.printRegisterComparison(System.out, "RSI");
		thread.printRegisterComparison(System.out, "RDI");

		//Test concrete value of RSI to see if the move executed
		ImmutablePair<String, String> rsicompare = thread.registerComparison("RSI");
		assertEquals(rsicompare.getLeft(), "deadbeef");
	}

	@Test
	// Test CMOV instruction
	// Using CMOVA (CMOV Above) on RSI and RDI, RDI = 0xdeadbeef and RSI = 0 (implied)
	public void testCMOVFail() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV RDI, 0xdeadbeef",
			"CMP RSI, RDI",
			"CMOVA RSI, RDI" };

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		//Execute instructions
		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);

		thread.printRegisterComparison(System.out, "RSI");
		thread.printRegisterComparison(System.out, "RDI");

		//Test concrete value of RSI to see if the move executed
		ImmutablePair<String, String> rsicompare = thread.registerComparison("RSI");
		assertEquals(rsicompare.getLeft(), "0");
	}

	@Test
	// Test size conversions
	// REP takes the memory at RSI and puts it in the memory location RDI, an RCX number of times
	// Not sure what the output looks like, current Z3 emulator can't handle REP instructions
	public void testConversion() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV EAX, dword ptr [RBP]",
			"CDQE"
		};

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RAX");

		//Test concrete value of RAX, should just be 0
		ImmutablePair<String, String> raxcompare = thread.registerComparison("RAX");
		assertEquals(raxcompare.getLeft(), "0");
	}

	@Test
	// Test IMUL
	// Code from 'arrayp' binary
	public void testIMUL() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();

		String[] instructions = new String[] {
			"MOV EAX, 0x3",
			"MOV EDX, 0x5",
			"IMUL ECX, EDX, 0x5" //EDX * EAX = 0xf
//				"SAR EDX, 0x3", //EDX = 1
//				"MOV EAX, ECX", 
//				"SAR EAX, 0x1f", //extend sign bit, EAX = 0
//				"MOV EAX, EDX", 
//				"IMUL EAX, EAX, 0x1a", //EAX = EAX * 26 = 26
//				"SUB ECX, EAX", //ECX = ECX - 0x1a
//				"MOV EAX, ECX",
//				"CDQE"
		};

		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		Msg.info(this, "ready for emulation");

		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);

		for (int i = 0; i < instructions.length; i++) {
			thread.stepInstruction();
		}

		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RCX");

		//Test concrete value of RCX, should be 0x19
		ImmutablePair<String, String> rcxcompare = thread.registerComparison("RCX");
		assertEquals(rcxcompare.getLeft(), "19");
	}
}
