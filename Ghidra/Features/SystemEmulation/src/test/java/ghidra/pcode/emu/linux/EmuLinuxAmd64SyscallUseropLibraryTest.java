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

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.sys.SyscallTestHelper;
import ghidra.pcode.emu.sys.SyscallTestHelper.SyscallName;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class EmuLinuxAmd64SyscallUseropLibraryTest extends AbstractGhidraHeadlessIntegrationTest {
	public enum Syscall implements SyscallName {
		/**
		 * These are a subset of the linux_amd64 system call numbers as of writing this test, but it
		 * doesn't really matter as long as the user program and syscall library agree.
		 */
		READ(0, "read"),
		WRITE(1, "write"),
		OPEN(2, "open"),
		CLOSE(3, "close"),
		READV(19, "readv"),
		WRITEV(20, "writev"),
		GROUP_EXIT(231, "group_exit");

		public final int number;
		public final String name;

		private Syscall(int number, String name) {
			this.number = number;
			this.name = name;
		}

		@Override
		public int getNumber() {
			return number;
		}

		@Override
		public String getName() {
			return name;
		}
	}

	protected final class LinuxAmd64PcodeEmulator extends PcodeEmulator {
		protected EmuLinuxAmd64SyscallUseropLibrary<byte[]> syscalls;

		public LinuxAmd64PcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new EmuLinuxAmd64SyscallUseropLibrary<>(this, fs, program);
			return syscalls;
		}
	}

	public static final SyscallTestHelper SYSCALL_HELPER =
		new SyscallTestHelper(List.of(Syscall.values()));

	protected static final byte[] BYTES_HW = "Hello, World!\n".getBytes();
	protected static final byte[] BYTES_HELLO = "Hello, ".getBytes();
	protected static final byte[] BYTES_WORLD = "World!\n".getBytes();

	Program program;
	Language language;
	Assembler asm;

	Register regRIP;
	Register regRAX;
	AddressSpace space;
	Address start;
	int size;
	MemoryBlock block;
	private EmuUnixFileSystem<byte[]> fs;
	PcodeArithmetic<byte[]> arithmetic;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("HelloWorld", "x86:LE:64:default", "gcc", this);
		language = program.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);

		regRIP = program.getRegister("RIP");
		regRAX = program.getRegister("RAX");
		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (Transaction tx = program.openTransaction("Initialize")) {
			block = program.getMemory()
					.createInitializedBlock(".text", start, size, (byte) 0, TaskMonitor.DUMMY,
						false);

			SYSCALL_HELPER.bootstrapProgram(program);
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
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX," + Syscall.WRITE.number,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",
				"MOV RAX," + Syscall.GROUP_EXIT.number,
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
			thread.getState().getVar(regRAX, Reason.INSPECT));
		assertArrayEquals(BYTES_HW, stdout.toByteArray());

		stepGroupExit(thread);
	}

	@Test
	public void testReadStdin() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX," + Syscall.READ.number,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",
				"MOV RAX," + Syscall.GROUP_EXIT.number,
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
			thread.getState().getVar(regRAX, Reason.INSPECT));
		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(space, 0x00400800, BYTES_HW.length, true, Reason.INSPECT));

		stepGroupExit(thread);
	}

	@Test
	public void testWritevStdout() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
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
				"MOV RAX," + Syscall.WRITEV.number,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA RSI,[0x" + iov + "]",
				"MOV RDX,2",
				"SYSCALL",
				"MOV RAX," + Syscall.GROUP_EXIT.number,
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

		assertEquals(BYTES_HW.length,
			arithmetic.toLong(thread.getState().getVar(regRAX, Reason.INSPECT), Purpose.OTHER));
		assertArrayEquals(BYTES_HW, stdout.toByteArray());

		stepGroupExit(thread);
	}

	@Test
	public void testReadvStdin() throws Exception {
		Address strHello;
		Address strWorld;
		try (Transaction tx = program.openTransaction("Initialize")) {
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
				"MOV RAX," + Syscall.READV.number,
				"MOV RDI," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA RSI,[0x" + iov + "]",
				"MOV RDX,2",
				"SYSCALL",
				"MOV RAX," + Syscall.GROUP_EXIT.number,
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

		assertEquals(BYTES_HW.length,
			arithmetic.toLong(thread.getState().getVar(regRAX, Reason.INSPECT), Purpose.OTHER));
		assertArrayEquals(BYTES_HELLO, emu.getSharedState()
				.getVar(space, strHello.getOffset(), BYTES_HELLO.length, true, Reason.INSPECT));
		assertArrayEquals(BYTES_WORLD, emu.getSharedState()
				.getVar(space, strWorld.getOffset(), BYTES_WORLD.length, true, Reason.INSPECT));

		stepGroupExit(thread);
	}

	@Test
	public void testOpenWriteClose() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV RAX," + Syscall.OPEN.number,
				"LEA RDI,[0x00400880]",
				"MOV RSI," + (AbstractEmuLinuxSyscallUseropLibrary.O_WRONLY |
					AbstractEmuLinuxSyscallUseropLibrary.O_CREAT),
				"MOV RDX," + (0600),
				"SYSCALL",
				"MOV RBP, RAX",

				"MOV RAX," + Syscall.WRITE.number,
				"MOV RDI,RBP",
				"LEA RSI,[0x00400800]",
				"MOV RDX," + BYTES_HW.length,
				"SYSCALL",

				"MOV RAX," + Syscall.CLOSE.number,
				"MOV RDI,RBP",

				"MOV RAX," + Syscall.GROUP_EXIT.number,
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

		EmuUnixFile<byte[]> file = fs.createOrGetFile("myfile", 0600);
		file.write(arithmetic, arithmetic.fromConst(0, 8), BYTES_HW);

		LinuxAmd64PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(space, 0x00400800, BYTES_HW.length, true, Reason.INSPECT));
	}
}
