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
package ghidra.pcode.emu.linux;

import static ghidra.pcode.emu.sys.EmuSyscallLibrary.SYSCALL_CONVENTION_NAME;
import static ghidra.pcode.emu.sys.EmuSyscallLibrary.SYSCALL_SPACE_NAME;
import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.*;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

public class EmuLinuxAmd64SyscallUseropLibraryTest extends AbstractGhidraHeadlessIntegrationTest {
	protected final class LinuxAmd64PcodeEmulator extends PcodeEmulator {
		protected EmuLinuxAmd64SyscallUseropLibrary<byte[]> syscalls;

		public LinuxAmd64PcodeEmulator() {
			super((SleighLanguage) program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new EmuLinuxAmd64SyscallUseropLibrary<>(this, fs, program);
			return syscalls;
		}
	}

	/**
	 * These are the linux_amd64 system call numbers as of writing this test, but it doesn't really
	 * matter as long as the user program and syscall library agree.
	 */
	protected static final int SYSCALLNO_READ = 0;
	protected static final int SYSCALLNO_WRITE = 1;
	protected static final int SYSCALLNO_OPEN = 2;
	protected static final int SYSCALLNO_CLOSE = 3;
	protected static final int SYSCALLNO_READV = 19;
	protected static final int SYSCALLNO_WRITEV = 20;
	protected static final int SYSCALLNO_GROUP_EXIT = 231;

	protected static final byte[] BYTES_HW = "Hello, World!\n".getBytes();
	protected static final byte[] BYTES_HELLO = "Hello, ".getBytes();
	protected static final byte[] BYTES_WORLD = "World!\n".getBytes();

	Program program;
	SleighLanguage language;
	Assembler asm;

	Register regRIP;
	Register regRAX;
	AddressSpace space;
	Address start;
	int size;
	MemoryBlock block;
	private EmuUnixFileSystem<byte[]> fs;
	PcodeArithmetic<byte[]> arithmetic;

	protected void placeSyscall(long number, String name) throws Exception {
		AddressSpace spaceSyscall =
			program.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		FunctionManager functions = program.getFunctionManager();

		Address addr = spaceSyscall.getAddress(number);
		functions.createFunction(name, addr, new AddressSet(addr), SourceType.USER_DEFINED)
				.setCallingConvention(SYSCALL_CONVENTION_NAME);
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("HelloWorld", "x86:LE:64:default", "gcc", this);
		language = (SleighLanguage) program.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);

		regRIP = program.getRegister("RIP");
		regRAX = program.getRegister("RAX");
		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			block = program.getMemory()
					.createInitializedBlock(".text", start, size, (byte) 0, TaskMonitor.DUMMY,
						false);

			// Fulfill requirements for the syscall userop library:
			// 1) The "/pointer" data type exists, so it knows the machine word size
			program.getDataTypeManager()
					.resolve(PointerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
			// 2) Create the syscall space and add those we'll be using
			Address startOther = program.getAddressFactory()
					.getAddressSpace(SpaceNames.OTHER_SPACE_NAME)
					.getAddress(0);
			MemoryBlock blockSyscall = program.getMemory()
					.createUninitializedBlock(SYSCALL_SPACE_NAME, startOther, 0x10000, true);
			blockSyscall.setPermissions(true, false, true);

			placeSyscall(SYSCALLNO_READ, "read");
			placeSyscall(SYSCALLNO_WRITE, "write");
			placeSyscall(SYSCALLNO_OPEN, "open");
			placeSyscall(SYSCALLNO_CLOSE, "close");
			placeSyscall(SYSCALLNO_READV, "readv");
			placeSyscall(SYSCALLNO_WRITEV, "writev");
			placeSyscall(SYSCALLNO_GROUP_EXIT, "group_exit");
		}

		fs = new BytesEmuUnixFileSystem();

		// I don't like waiting on this, just to fail during setup. Put it last.
		asm = Assemblers.getAssembler(program);
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
	}

	public LinuxAmd64PcodeEmulator prepareEmulator() throws Exception {
		LinuxAmd64PcodeEmulator emu = new LinuxAmd64PcodeEmulator();
		// The emulator is not itself bound to the program or a trace, so copy bytes in
		byte[] buf = new byte[size];
		assertEquals(size, block.getBytes(start, buf));
		emu.getSharedState().setVar(space, start.getOffset(), size, true, buf);
		return emu;
	}

	public PcodeThread<byte[]> launchThread(LinuxAmd64PcodeEmulator emu, Address pc) {
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(start);
		thread.overrideContextWithDefault();
		thread.reInitialize();
		return thread;
	}

	public void stepGroupExit(PcodeThread<byte[]> thread) {
		// Step up to the group_exit
		thread.stepInstruction(2);
		// Then verify the syscall interrupts execution
		try {
			thread.stepInstruction();
			fail();
		}
		catch (EmuProcessExitedException e) {
			// pass
		}
	}

	public void execute(PcodeThread<byte[]> thread) {
		try {
			thread.stepInstruction(1000);
			fail();
		}
		catch (EmuProcessExitedException e) {
		}
	}

	@Test
	public void testWriteStdout() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_WRITE,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",
				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(space.getAddress(0x00400800), BYTES_HW);
		}

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));

		// Step through write and verify return value and actual output effect
		thread.stepInstruction(5);
		assertArrayEquals(arithmetic.fromConst(BYTES_HW.length, regRAX.getNumBytes()),
			thread.getState().getVar(regRAX));
		assertArrayEquals(BYTES_HW, stdout.toByteArray());

		stepGroupExit(thread);
	}

	@Test
	public void testReadStdin() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_READ,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",
				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
		}

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));

		// Step through write and verify return value and actual output effect
		thread.stepInstruction(5);
		assertArrayEquals(arithmetic.fromConst(BYTES_HW.length, regRAX.getNumBytes()),
			thread.getState().getVar(regRAX));
		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(space, 0x00400800, BYTES_HW.length, true));

		stepGroupExit(thread);
	}

	@Test
	public void testWritevStdout() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			Address data = space.getAddress(0x00400800);
			ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);

			Address strHello = data.add(buf.position());
			buf.put(BYTES_HELLO);
			Address endHello = data.add(buf.position());
			Address iov = data.add(buf.position());
			buf.putLong(strHello.getOffset());
			buf.putLong(endHello.subtract(strHello));
			int posIov1base = buf.position();
			buf.putLong(0);
			int posIov1len = buf.position();
			buf.putLong(0);
			Address strWorld = data.add(buf.position());
			buf.put(BYTES_WORLD);
			Address endWorld = data.add(buf.position());
			// Backpatch
			buf.putLong(posIov1base, strWorld.getOffset());
			buf.putLong(posIov1len, endWorld.subtract(strWorld));

			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_WRITEV,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA RSI,[0x" + iov + "]",
				"MOV RDX,2",
				"SYSCALL",
				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(data, buf.array());
		}

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));

		// Step through writev and verify return value and actual output effect
		thread.stepInstruction(5);

		assertEquals(BigInteger.valueOf(BYTES_HW.length),
			arithmetic.toConcrete(thread.getState().getVar(regRAX)));
		assertArrayEquals(BYTES_HW, stdout.toByteArray());

		stepGroupExit(thread);
	}

	@Test
	public void testReadvStdin() throws Exception {
		Address strHello;
		Address strWorld;
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			Address data = space.getAddress(0x00400800);
			ByteBuffer buf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);

			strHello = data.add(buf.position());
			buf.put(new byte[BYTES_HELLO.length]);
			Address endHello = data.add(buf.position());
			Address iov = data.add(buf.position());
			buf.putLong(strHello.getOffset());
			buf.putLong(endHello.subtract(strHello));
			int posIov1base = buf.position();
			buf.putLong(0);
			int posIov1len = buf.position();
			buf.putLong(0);
			strWorld = data.add(buf.position());
			buf.put(new byte[BYTES_WORLD.length]);
			Address endWorld = data.add(buf.position());
			// Backpatch
			buf.putLong(posIov1base, strWorld.getOffset());
			buf.putLong(posIov1len, endWorld.subtract(strWorld));

			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_READV,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA RSI,[0x" + iov + "]",
				"MOV RDX,2",
				"SYSCALL",
				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(data, buf.array());
		}

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));

		// Step through readv and verify return value and actual output effect
		thread.stepInstruction(5);

		assertEquals(BigInteger.valueOf(BYTES_HW.length),
			arithmetic.toConcrete(thread.getState().getVar(regRAX)));
		assertArrayEquals(BYTES_HELLO,
			emu.getSharedState().getVar(space, strHello.getOffset(), BYTES_HELLO.length, true));
		assertArrayEquals(BYTES_WORLD,
			emu.getSharedState().getVar(space, strWorld.getOffset(), BYTES_WORLD.length, true));

		stepGroupExit(thread);
	}

	@Test
	public void testOpenWriteClose() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_OPEN,
				"LEA RDI,[0x00400880]",
				"MOV RSI," + (AbstractEmuLinuxSyscallUseropLibrary.O_WRONLY |
					AbstractEmuLinuxSyscallUseropLibrary.O_CREAT),
				"MOV RDX," + (0600),
				"SYSCALL",
				"MOV RBP, RAX",

				"MOV RAX," + SYSCALLNO_WRITE,
				"MOV RDI,RBP",
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",

				"MOV RAX," + SYSCALLNO_CLOSE,
				"MOV RDI,RBP",

				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(space.getAddress(0x00400800), BYTES_HW);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		EmuUnixFile<byte[]> file = fs.getFile("myfile");
		byte[] bytes = new byte[BYTES_HW.length];
		file.read(arithmetic, arithmetic.fromConst(0, 8), bytes);
		assertArrayEquals(BYTES_HW, bytes);
	}

	@Test
	public void testOpenReadClose() throws Exception {
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			asm.assemble(start,
				"MOV RAX," + SYSCALLNO_OPEN,
				"LEA RDI,[0x00400880]",
				"MOV RSI," + (AbstractEmuLinuxSyscallUseropLibrary.O_RDONLY),
				"MOV RDX," + (0600),
				"SYSCALL",
				"MOV RBP, RAX",

				"MOV RAX," + SYSCALLNO_READ,
				"MOV RDI,RBP",
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",

				"MOV RAX," + SYSCALLNO_CLOSE,
				"MOV RDI,RBP",

				"MOV RAX," + SYSCALLNO_GROUP_EXIT,
				"MOV RDI,0",
				"SYSCALL");
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		EmuUnixFile<byte[]> file = fs.createOrGetFile("myfile", 0600);
		file.write(arithmetic, arithmetic.fromConst(0, 8), BYTES_HW);

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(space, 0x00400800, BYTES_HW.length, true));
	}
}
