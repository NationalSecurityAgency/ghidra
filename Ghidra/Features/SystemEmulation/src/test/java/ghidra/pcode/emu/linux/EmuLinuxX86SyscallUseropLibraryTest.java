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
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class EmuLinuxX86SyscallUseropLibraryTest extends AbstractGhidraHeadlessIntegrationTest {
	public enum Syscall implements SyscallName {
		/**
		 * These are the linux_x86 system call numbers as of writing this test, but it doesn't
		 * really matter as long as the user program and syscall library agree.
		 */
		EXIT(1, "exit"),
		READ(3, "read"),
		WRITE(4, "write"),
		OPEN(5, "open"),
		CLOSE(6, "close"),
		READV(145, "readv"),
		WRITEV(146, "writev");

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

	protected final class LinuxX86PcodeEmulator extends PcodeEmulator {
		protected EmuLinuxX86SyscallUseropLibrary<byte[]> syscalls;

		public LinuxX86PcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new EmuLinuxX86SyscallUseropLibrary<>(this, fs, program);
			return syscalls;
		}
	}

	public static final SyscallTestHelper SYSCALL_HELPER =
		new SyscallTestHelper(List.of(Syscall.values()));

	protected static final byte[] BYTES_HW = "Hello, World!\n".getBytes();
	protected static final byte[] BYTES_HELLO = "Hello, ".getBytes();
	protected static final byte[] BYTES_WORLD = "World!\n".getBytes();

	Program program;
	SleighLanguage language;
	Assembler asm;

	Register regEIP;
	Register regEAX;
	AddressSpace space;
	Address start;
	int size;
	MemoryBlock block;
	private EmuUnixFileSystem<byte[]> fs;
	PcodeArithmetic<byte[]> arithmetic;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("HelloWorld", "x86:LE:32:default", "gcc", this);
		language = (SleighLanguage) program.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);

		regEIP = program.getRegister("EIP");
		regEAX = program.getRegister("EAX");
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

	public LinuxX86PcodeEmulator prepareEmulator() throws Exception {
		LinuxX86PcodeEmulator emu = new LinuxX86PcodeEmulator();
		// The emulator is not itself bound to the program or a trace, so copy bytes in
		byte[] buf = new byte[size];
		assertEquals(size, block.getBytes(start, buf));
		emu.getSharedState().setVar(space, start.getOffset(), size, true, buf);
		return emu;
	}

	public PcodeThread<byte[]> launchThread(LinuxX86PcodeEmulator emu, Address pc) {
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
				"MOV EAX," + Syscall.WRITE.number,
				"MOV EBX," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA ECX,[0x00400800]",
				"MOV EDX," + BYTES_HW.length,
				"INT 0x80",
				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
			block.putBytes(space.getAddress(0x00400800), BYTES_HW);
		}

		LinuxX86PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));

		// Step through write and verify return value and actual output effect
		thread.stepInstruction(5);
		assertArrayEquals(arithmetic.fromConst(BYTES_HW.length, regEAX.getNumBytes()),
			thread.getState().getVar(regEAX, Reason.INSPECT));
		assertArrayEquals(BYTES_HW, stdout.toByteArray());

		stepGroupExit(thread);
	}

	@Test
	public void testReadStdin() throws Exception {
		try (Transaction tx = program.openTransaction("Initialize")) {
			asm.assemble(start,
				"MOV EAX," + Syscall.READ.number,
				"MOV EBX," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA ECX,[0x00400800]",
				"MOV EDX," + BYTES_HW.length,
				"INT 0x80",
				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
		}

		LinuxX86PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));

		// Step through write and verify return value and actual output effect
		thread.stepInstruction(5);
		assertArrayEquals(arithmetic.fromConst(BYTES_HW.length, regEAX.getNumBytes()),
			thread.getState().getVar(regEAX, Reason.INSPECT));
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
			buf.putInt((int) strHello.getOffset());
			buf.putInt((int) endHello.subtract(strHello));
			int posIov1base = buf.position();
			buf.putInt(0);
			int posIov1len = buf.position();
			buf.putInt(0);
			Address strWorld = data.add(buf.position());
			buf.put(BYTES_WORLD);
			Address endWorld = data.add(buf.position());
			// Backpatch
			buf.putInt(posIov1base, (int) strWorld.getOffset());
			buf.putInt(posIov1len, (int) endWorld.subtract(strWorld));

			asm.assemble(start,
				"MOV EAX," + Syscall.WRITEV.number,
				"MOV EBX," + EmuUnixFileDescriptor.FD_STDOUT,
				"LEA ECX,[0x" + iov + "]",
				"MOV EDX,2",
				"INT 0x80",
				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
			block.putBytes(data, buf.array());
		}

		LinuxX86PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));

		// Step through writev and verify return value and actual output effect
		thread.stepInstruction(5);

		assertEquals(BYTES_HW.length,
			arithmetic.toLong(thread.getState().getVar(regEAX, Reason.INSPECT), Purpose.OTHER));
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
			buf.putInt((int) strHello.getOffset());
			buf.putInt((int) endHello.subtract(strHello));
			int posIov1base = buf.position();
			buf.putInt(0);
			int posIov1len = buf.position();
			buf.putInt(0);
			strWorld = data.add(buf.position());
			buf.put(new byte[BYTES_WORLD.length]);
			Address endWorld = data.add(buf.position());
			// Backpatch
			buf.putInt(posIov1base, (int) strWorld.getOffset());
			buf.putInt(posIov1len, (int) endWorld.subtract(strWorld));

			asm.assemble(start,
				"MOV EAX," + Syscall.READV.number,
				"MOV EBX," + EmuUnixFileDescriptor.FD_STDIN,
				"LEA ECX,[0x" + iov + "]",
				"MOV EDX,2",
				"INT 0x80",
				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
			block.putBytes(data, buf.array());
		}

		LinuxX86PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		emu.syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));

		// Step through readv and verify return value and actual output effect
		thread.stepInstruction(5);

		assertEquals(BYTES_HW.length,
			arithmetic.toLong(thread.getState().getVar(regEAX, Reason.INSPECT), Purpose.OTHER));
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
				"MOV EAX," + Syscall.OPEN.number,
				"LEA EBX,[0x00400880]",
				"MOV ECX," + (AbstractEmuLinuxSyscallUseropLibrary.O_WRONLY |
					AbstractEmuLinuxSyscallUseropLibrary.O_CREAT),
				"MOV EDX," + (0600),
				"INT 0x80",
				"MOV EBP, EAX",

				"MOV EAX," + Syscall.WRITE.number,
				"MOV EBX,EBP",
				"LEA ECX,[0x00400800]",
				"MOV EDX," + BYTES_HW.length,
				"INT 0x80",

				"MOV EAX," + Syscall.CLOSE.number,
				"MOV EBX,EBP",

				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
			block.putBytes(space.getAddress(0x00400800), BYTES_HW);
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		LinuxX86PcodeEmulator emu = prepareEmulator();
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
				"MOV EAX," + Syscall.OPEN.number,
				"LEA EBX,[0x00400880]",
				"MOV ECX," + (AbstractEmuLinuxSyscallUseropLibrary.O_RDONLY),
				"MOV EDX," + (0600),
				"INT 0x80",
				"MOV EBP, EAX",

				"MOV EAX," + Syscall.READ.number,
				"MOV EBX,EBP",
				"LEA ECX,[0x00400800]",
				"MOV EDX," + BYTES_HW.length,
				"INT 0x80",

				"MOV EAX," + Syscall.CLOSE.number,
				"MOV EBX,EBP",

				"MOV EAX," + Syscall.EXIT.number,
				"MOV EBX,0",
				"INT 0x80");
			block.putBytes(space.getAddress(0x00400880), "myfile\0".getBytes());
		}

		EmuUnixFile<byte[]> file = fs.createOrGetFile("myfile", 0600);
		file.write(arithmetic, arithmetic.fromConst(0, 8), BYTES_HW);

		LinuxX86PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(space, 0x00400800, BYTES_HW.length, true, Reason.INSPECT));
	}
}
