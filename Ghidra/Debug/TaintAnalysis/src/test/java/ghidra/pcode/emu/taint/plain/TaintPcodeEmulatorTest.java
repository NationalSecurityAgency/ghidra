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
package ghidra.pcode.emu.taint.plain;

import static org.junit.Assert.*;

import java.io.IOException;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.*;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.linux.AbstractEmuLinuxSyscallUseropLibrary;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest.Syscall;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.taint.lib.TaintEmuUnixFileSystem;
import ghidra.pcode.emu.taint.lib.TaintFileReadsLinuxAmd64SyscallLibrary;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.taint.model.TaintSet;
import ghidra.taint.model.TaintVec;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class TaintPcodeEmulatorTest extends AbstractGhidraHeadlessIntegrationTest {
	protected final class LinuxAmd64TaintPcodeEmulator extends TaintPcodeEmulator {
		public LinuxAmd64TaintPcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<Pair<byte[], TaintVec>> createUseropLibrary() {
			return super.createUseropLibrary()
					.compose(new TaintFileReadsLinuxAmd64SyscallLibrary(this, fs, program));
		}
	}

	protected static final byte[] BYTES_HW = "Hello, World!\n".getBytes();

	private Program program;
	private Language language;
	private AddressSpace space;
	private Address start;
	private int size;
	private MemoryBlock block;
	private Assembler asm;

	private TaintEmuUnixFileSystem fs;
	private TaintPcodeEmulator emulator;

	@Before
	public void setUpTaintTest() throws Exception {
		program = createDefaultProgram("HelloTaint", "x86:LE:64:default", "gcc", this);
		language = program.getLanguage();
		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (Transaction tx = program.openTransaction("Initialize")) {
			block = program.getMemory()
					.createInitializedBlock(".text", start, size, (byte) 0, TaskMonitor.DUMMY,
						false);

			EmuLinuxAmd64SyscallUseropLibraryTest.SYSCALL_HELPER.bootstrapProgram(program);
		}

		asm = Assemblers.getAssembler(program);

		fs = new TaintEmuUnixFileSystem();
		emulator = new LinuxAmd64TaintPcodeEmulator();
	}

	@After
	public void tearDownTaintTest() throws Exception {
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

	public PcodeThread<?> launchThread(Address pc) {
		PcodeThread<?> thread = emulator.newThread();
		thread.overrideCounter(start);
		thread.overrideContextWithDefault();
		thread.reInitialize();
		return thread;
	}

	public void execute(PcodeThread<?> thread) {
		try {
			thread.stepInstruction(1000);
			fail();
		}
		catch (EmuProcessExitedException e) {
		}
	}

	@Test
	public void testZeroByXor()
			throws AssemblySyntaxException, AssemblySemanticException, IOException {
		PcodeThread<Pair<byte[], TaintVec>> thread = emulator.newThread();
		AddressSpace dyn = language.getDefaultSpace();

		Address entry = dyn.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		buffer.assemble("XOR RAX, RAX");
		byte[] prog = buffer.getBytes();

		Register regRAX = language.getRegister("RAX");
		Pair<byte[], TaintVec> initRAX =
			Pair.of(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, TaintVec.array("RAX", 0, 8));
		thread.getState().setVar(regRAX, initRAX);

		emulator.getSharedState().getLeft().setVar(dyn, 0x00400000, prog.length, true, prog);

		thread.overrideCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		Pair<byte[], TaintVec> endRAX = thread.getState().getVar(regRAX, Reason.INSPECT);
		assertEquals(0,
			Utils.bytesToLong(endRAX.getLeft(), regRAX.getNumBytes(), language.isBigEndian()));
		assertEquals(TaintVec.empties(regRAX.getNumBytes()), endRAX.getRight());
	}

	@Test
	public void testTaintFileReads() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX," + Syscall.OPEN.number,
				"LEA RDI,[0x00400880]",
				"MOV RSI," + (AbstractEmuLinuxSyscallUseropLibrary.O_RDONLY),
				"MOV RDX," + (0600),
				"SYSCALL",
				"MOV RBP, RAX",

				"MOV RAX," + Syscall.READ.number,
				"MOV RDI,RBP",
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",

				"MOV RAX," + Syscall.CLOSE.number,
				"MOV RDI,RBP",

				"MOV RAX," + Syscall.GROUP_EXIT.number,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		fs.putTaintedFile("myfile", BYTES_HW);

		prepareEmulator();
		PcodeThread<?> thread = launchThread(start);
		execute(thread);

		Pair<byte[], TaintVec> buf = emulator.getSharedState()
				.getVar(space, 0x00400800, BYTES_HW.length, true, Reason.INSPECT);
		assertArrayEquals(BYTES_HW, buf.getLeft());
		assertEquals(TaintVec.array("myfile", 0, BYTES_HW.length), buf.getRight());
	}

	@Test
	public void testTaintViaSleigh() throws Exception {
		prepareEmulator();
		PcodeThread<?> thread = launchThread(start);
		thread.getExecutor().executeSleigh("*:8 0x00400000:8 = taint_arr(*:8 0x004000000:8);");

		Pair<byte[], TaintVec> taintVal =
			emulator.getSharedState().getVar(space, 0x00400000, 8, true, Reason.INSPECT);
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 }, taintVal.getLeft());
		assertEquals(TaintVec.array("arr_0", 0, 8), taintVal.getRight());
	}

	@Test
	public void testTaintIndirectRead() throws Exception {
		PcodeThread<Pair<byte[], TaintVec>> thread = emulator.newThread();
		AddressSpace dyn = language.getDefaultSpace();

		Address entry = dyn.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		buffer.assemble("MOV RBX, qword ptr [RAX]");
		byte[] prog = buffer.getBytes();

		Register regRAX = language.getRegister("RAX");
		Register regRBX = language.getRegister("RBX");
		Pair<byte[], TaintVec> initRAX =
			Pair.of(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, TaintVec.array("RAX", 0, 8));
		thread.getState().setVar(regRAX, initRAX);
		Pair<byte[], TaintVec> initMem =
			Pair.of(new byte[] { 9, 10, 11, 12, 13, 14, 15, 16 }, TaintVec.array("mem", 0, 8));
		emulator.getSharedState().setVar(dyn, 0x0807060504030201L, 8, true, initMem);
		emulator.getSharedState().getLeft().setVar(dyn, 0x00400000, prog.length, true, prog);

		thread.overrideCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		Pair<byte[], TaintVec> endRBX = thread.getState().getVar(regRBX, Reason.INSPECT);
		assertEquals(0x100f0e0d0c0b0a09L,
			Utils.bytesToLong(endRBX.getLeft(), regRBX.getNumBytes(), language.isBigEndian()));
		TaintSet fromIndirect = TaintVec.array("RAX", 0, 8).union().tagged("indR");
		TaintVec exp = TaintVec.array("mem", 0, 8).eachUnion(fromIndirect);
		assertEquals(exp, endRBX.getRight());
	}

	@Test
	public void testTaintIndrectWrite() throws Exception {

		PcodeThread<Pair<byte[], TaintVec>> thread = emulator.newThread();
		AddressSpace dyn = language.getDefaultSpace();

		Address entry = dyn.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		buffer.assemble("MOV qword ptr [RAX], RBX");
		byte[] prog = buffer.getBytes();

		Register regRAX = language.getRegister("RAX");
		Register regRBX = language.getRegister("RBX");
		Pair<byte[], TaintVec> initRAX =
			Pair.of(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, TaintVec.array("RAX", 0, 8));
		thread.getState().setVar(regRAX, initRAX);
		Pair<byte[], TaintVec> initRBX =
			Pair.of(new byte[] { 9, 10, 11, 12, 13, 14, 15, 16 }, TaintVec.array("RBX", 0, 8));
		thread.getState().setVar(regRBX, initRBX);
		emulator.getSharedState().getLeft().setVar(dyn, 0x00400000, prog.length, true, prog);

		thread.overrideCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		Pair<byte[], TaintVec> endMem =
			emulator.getSharedState().getVar(dyn, 0x0807060504030201L, 8, true, Reason.INSPECT);
		assertEquals(0x100f0e0d0c0b0a09L,
			Utils.bytesToLong(endMem.getLeft(), regRBX.getNumBytes(), language.isBigEndian()));
		TaintSet fromIndirect = TaintVec.array("RAX", 0, 8).union().tagged("indW");
		TaintVec exp = TaintVec.array("RBX", 0, 8).eachUnion(fromIndirect);
		assertEquals(exp, endMem.getRight());
	}

	@Test
	public void testMovReplaces()
			throws AssemblySyntaxException, AssemblySemanticException, IOException {
		PcodeThread<Pair<byte[], TaintVec>> thread = emulator.newThread();
		AddressSpace dyn = language.getDefaultSpace();

		Address entry = dyn.getAddress(0x00400000);
		Assembler asm = Assemblers.getAssembler(language);
		AssemblyBuffer buffer = new AssemblyBuffer(asm, entry);
		buffer.assemble("MOV RAX, RBX");
		byte[] prog = buffer.getBytes();

		Register regRAX = language.getRegister("RAX");
		Pair<byte[], TaintVec> initRAX =
			Pair.of(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, TaintVec.array("RAX", 0, 8));
		thread.getState().setVar(regRAX, initRAX);

		emulator.getSharedState().getLeft().setVar(dyn, 0x00400000, prog.length, true, prog);

		thread.overrideCounter(entry);
		thread.overrideContextWithDefault();
		thread.stepInstruction();

		Pair<byte[], TaintVec> endRAX = thread.getState().getVar(regRAX, Reason.INSPECT);
		assertEquals(0,
			Utils.bytesToLong(endRAX.getLeft(), regRAX.getNumBytes(), language.isBigEndian()));
		assertEquals(TaintVec.empties(regRAX.getNumBytes()), endRAX.getRight());
	}
}
