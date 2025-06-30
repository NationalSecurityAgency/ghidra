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
package ghidra.pcode.emu.symz3.plain;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.Context;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest.Syscall;
import ghidra.pcode.emu.symz3.SymZ3PcodeThread;
import ghidra.pcode.emu.symz3.lib.*;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.symz3.model.SymValueZ3;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class SymZ3PcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {
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
	public void testAHregister() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"ADD AH, AH",
			"MOV RCX, RAX" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
		String rcxContents = thread.registerComparison("RCX").getRight();
		assertEquals("(RAX[16:48] :: (RAX[8:8] * (0x2:8)) :: RAX[0:8])", rcxContents);
	}

	@Test
	public void testLAHF() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"LAHF" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		PcodeThread<?> thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
	}

	@Test
	public void testSAHFandPUSHF() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] { "SAHF", "PUSHF" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		PcodeThread<?> thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
	}

	@Test
	public void testFetchofBoolean() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"CLC",
			"JA 0x00400632" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		PcodeThread<?> thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
	}

	@Test
	public void testAdditionSummary() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"ADD RAX, RCX",
			"ADD RAX, RBX" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RAX");
		ImmutablePair<String, String> comparison = thread.registerComparison("RAX");
		assertEquals(comparison.getRight(), "(RAX + RCX + RBX)");
		Msg.info(this, "Z3 Version: " + com.microsoft.z3.Version.getFullVersion());
	}

	@Test
	public void testSymZ3Twobytes() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV dword ptr [RBP + -0x18],EAX",
				"MOVZX EAX,byte ptr [RBP + -0x10]",
				"MOVZX EAX,AL",
				"SHL EAX,0x8",
				"MOV EDX,EAX",
				"MOVZX EAX,byte ptr [RBP + -0xf]",
				"MOVZX EAX,AL",
				"OR EAX,EDX",
				"MOV word ptr [RBP + -0x1a],AX",
				"CMP word ptr [RBP + -0x1a],0x6162",
				"JZ 0x00400632",
				"MOV byte ptr [RBP + -0x11],0x30",
				"MOV RAX," + Syscall.GROUP_EXIT.number,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);
		try {
			thread.run();
		}
		catch (EmuProcessExitedException e) {
			Msg.info(this, "exit");
		}
		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RAX");
		ImmutablePair<String, String> comparison = thread.registerComparison("RAX");
		assertEquals("(0x" + comparison.getLeft() + ":64)", comparison.getRight()); // same syscall

		// TODO:  need an assert about the precondition
	}

	@Test
	public void testIsNegativeConstant() throws Exception {
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			BitVecExpr negone = ctx.mkBV(-1, 32);
			Msg.info(this, "as an expr: " + negone.getSExpr());
			Msg.info(this, z3p.isNegativeConstant(negone));
			assertEquals(BigInteger.ONE, z3p.isNegativeConstant(negone));
		}
	}

	@Test
	public void testSerialization() throws Exception {
		try (Context ctx = new Context()) {
			SymValueZ3 one = new SymValueZ3(ctx, ctx.mkBV(123, 8));
			Msg.info(this, one.getBitVecExpr(ctx).getSExpr());
			//SymValueZ3 b = new SymValueZ3(ctx,ctx.mkTrue());
			//Msg.info(this, b.getBoolExpr(ctx).getSExpr());
		}
	}

	@Test
	public void testSimpleMemory() throws Exception {
		emulator = new LinuxAmd64SymZ3PcodeEmulator();
		String[] instructions = new String[] {
			"MOV EAX, 0xdeadbeef",
			"MOV dword ptr [RBP + -0x18],EAX",
			"MOV ECX, dword ptr[RBP + -0x18]" };
		try (Transaction tid = program.openTransaction("Initialize")) {
			asm.assemble(start, instructions);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}
		prepareEmulator();
		SymZ3PcodeThread thread = launchThread(start);
		thread.stepInstruction(instructions.length);
		emulator.printCompleteSummary(System.out);
		thread.printRegisterComparison(System.out, "RAX");
		thread.printRegisterComparison(System.out, "RCX");
		thread.printMemoryComparisonRegPlusOffset(System.out, "RBP", -0x18);
	}
}
