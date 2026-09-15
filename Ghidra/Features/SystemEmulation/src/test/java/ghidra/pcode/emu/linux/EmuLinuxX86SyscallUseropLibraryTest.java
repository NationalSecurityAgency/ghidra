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
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.*;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibraryTest.CaptureUseropLibrary;
import ghidra.pcode.emu.sys.EmuProcessExitedException;
import ghidra.pcode.emu.sys.SyscallTestHelper;
import ghidra.pcode.emu.sys.SyscallTestHelper.SyscallName;
import ghidra.pcode.emu.unix.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
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

		public LinuxX86PcodeEmulator() {
			super(program.getLanguage());
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			syscalls = new EmuLinuxX86SyscallUseropLibrary<>(this, fs, program);
			capture = new CaptureUseropLibrary();
			return syscalls.compose(capture);
		}

		@Override
		protected BytesPcodeThread createThread(String name) {
			return new BytesPcodeThread(name, this) {
				int count = 0;

				@Override
				protected PcodeThreadExecutor<byte[]> createExecutor() {
					return new PcodeThreadExecutor<>(this) {
						@Override
						public void stepOp(PcodeOp op, PcodeFrame frame,
								PcodeUseropLibrary<byte[]> library) {
							count++;
							if (count > 1000) {
								fail("Probably an infinite loop");
							}
							super.stepOp(op, frame, library);
						}
					};
				}
			};
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

	AddressSpace space;
	Address start;
	int size;
	MemoryBlock block;
	EmuLinuxX86SyscallUseropLibrary<byte[]> syscalls;
	CaptureUseropLibrary capture;
	EmuUnixFileSystem<byte[]> fs;
	PcodeArithmetic<byte[]> arithmetic;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("HelloWorld", "x86:LE:32:default", "gcc", this);
		language = (SleighLanguage) program.getLanguage();
		arithmetic = BytesPcodeArithmetic.forLanguage(language);

		space = program.getAddressFactory().getDefaultAddressSpace();
		start = space.getAddress(0x00400000);
		size = 0x1000;

		try (Transaction _ = program.openTransaction("Initialize")) {
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

	protected PcodeEmulator createEmulator() {
		return new LinuxX86PcodeEmulator();
	}

	public PcodeEmulator prepareEmulator() throws Exception {
		PcodeEmulator emu = createEmulator();
		// The emulator is not itself bound to the program or a trace, so copy bytes in
		byte[] buf = new byte[size];
		assertEquals(size, block.getBytes(start, buf));
		emu.getSharedState().setVar(space, start.getOffset(), size, true, buf);
		return emu;
	}

	public PcodeThread<byte[]> launchThread(PcodeEmulator emu, Address pc) {
		PcodeThread<byte[]> thread = emu.newThread();
		thread.overrideCounter(start);
		thread.overrideContextWithDefault();
		thread.reInitialize();
		return thread;
	}

	public void execute(PcodeThread<byte[]> thread) {
		try {
			thread.run();
			fail();
		}
		catch (EmuProcessExitedException e) {
		}
	}

	@Test
	public void testWriteStdout() throws Exception {
		Address hwAddr = space.getAddress(0x00400800);

		AssemblyBuffer buf = new AssemblyBuffer(asm, start);
		buf.assemble("MOV EAX, %d".formatted(Syscall.WRITE.number));
		buf.assemble("MOV EBX, %d".formatted(EmuUnixFileDescriptor.FD_STDOUT));
		buf.assemble("LEA ECX, [0x%x]".formatted(hwAddr.getOffset()));
		buf.assemble("MOV EDX, %d".formatted(BYTES_HW.length));
		buf.assemble("INT 0x80");
		final Address captureAt = buf.getNext();
		buf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		buf.assemble("MOV EBX, 0");
		buf.assemble("INT 0x80");
		buf.assemble("JMP 0x%x".formatted(buf.getNext().getOffset())); // Snuff JIT look-ahead
		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, buf.getBytes());
			block.putBytes(hwAddr, BYTES_HW);
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		thread.inject(captureAt, "capture(EAX); emu_exec_decoded();");

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));
		execute(thread);

		assertEquals(List.of((long) BYTES_HW.length), capture.captured);
		assertArrayEquals(BYTES_HW, stdout.toByteArray());
	}

	@Test
	public void testReadStdin() throws Exception {
		Address hwAddr = space.getAddress(0x00400800);

		AssemblyBuffer buf = new AssemblyBuffer(asm, start);
		buf.assemble("MOV EAX, %d".formatted(Syscall.READ.number));
		buf.assemble("MOV EBX, %d".formatted(EmuUnixFileDescriptor.FD_STDIN));
		buf.assemble("LEA ECX, [0x%x]".formatted(hwAddr.getOffset()));
		buf.assemble("MOV EDX, %d".formatted(BYTES_HW.length));
		buf.assemble("INT 0x80");
		final Address captureAt = buf.getNext();
		buf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		buf.assemble("MOV EBX, 0");
		buf.assemble("INT 0x80");
		buf.assemble("JMP 0x%x".formatted(buf.getNext().getOffset())); // Snuff JIT look-ahead
		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, buf.getBytes());
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		thread.inject(captureAt, "capture(EAX); emu_exec_decoded();");

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));
		execute(thread);

		assertEquals(List.of((long) BYTES_HW.length), capture.captured);
		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(hwAddr, BYTES_HW.length, true, Reason.INSPECT));
	}

	@Test
	public void testWritevStdout() throws Exception {
		Address data = space.getAddress(0x00400800);

		ByteBuffer dBuf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
		Address strHello = data.add(dBuf.position());
		dBuf.put(BYTES_HELLO);
		Address endHello = data.add(dBuf.position());
		Address iov = data.add(dBuf.position());
		dBuf.putInt((int) strHello.getOffset());
		dBuf.putInt((int) endHello.subtract(strHello));
		int posIov1base = dBuf.position();
		dBuf.putInt(0);
		int posIov1len = dBuf.position();
		dBuf.putInt(0);
		Address strWorld = data.add(dBuf.position());
		dBuf.put(BYTES_WORLD);
		Address endWorld = data.add(dBuf.position());
		// Backpatch
		dBuf.putInt(posIov1base, (int) strWorld.getOffset());
		dBuf.putInt(posIov1len, (int) endWorld.subtract(strWorld));

		AssemblyBuffer cBuf = new AssemblyBuffer(asm, start);
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.WRITEV.number));
		cBuf.assemble("MOV EBX, %d".formatted(EmuUnixFileDescriptor.FD_STDOUT));
		cBuf.assemble("LEA ECX, [0x%x]".formatted(iov.getOffset()));
		cBuf.assemble("MOV EDX, 2");
		cBuf.assemble("INT 0x80");
		final Address captureAt = cBuf.getNext();
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		cBuf.assemble("MOV EBX, 0");
		cBuf.assemble("INT 0x80");
		cBuf.assemble("JMP 0x%x".formatted(cBuf.getNext().getOffset())); // Snuff JIT look-ahead
		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, cBuf.getBytes());
			block.putBytes(data, dBuf.array());
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		thread.inject(captureAt, "capture(EAX); emu_exec_decoded();");

		// Capture stdout into a byte array
		ByteArrayOutputStream stdout = new ByteArrayOutputStream();
		syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDOUT,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), null, stdout));
		execute(thread);

		assertEquals(List.of((long) BYTES_HW.length), capture.captured);
		assertArrayEquals(BYTES_HW, stdout.toByteArray());
	}

	@Test
	public void testReadvStdin() throws Exception {
		Address data = space.getAddress(0x00400800);

		ByteBuffer dBuf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
		Address strHello = data.add(dBuf.position());
		dBuf.put(new byte[BYTES_HELLO.length]);
		Address endHello = data.add(dBuf.position());
		Address iov = data.add(dBuf.position());
		dBuf.putInt((int) strHello.getOffset());
		dBuf.putInt((int) endHello.subtract(strHello));
		int posIov1base = dBuf.position();
		dBuf.putInt(0);
		int posIov1len = dBuf.position();
		dBuf.putInt(0);
		Address strWorld = data.add(dBuf.position());
		dBuf.put(new byte[BYTES_WORLD.length]);
		Address endWorld = data.add(dBuf.position());
		// Backpatch
		dBuf.putInt(posIov1base, (int) strWorld.getOffset());
		dBuf.putInt(posIov1len, (int) endWorld.subtract(strWorld));

		AssemblyBuffer cBuf = new AssemblyBuffer(asm, start);
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.READV.number));
		cBuf.assemble("MOV EBX, %d".formatted(EmuUnixFileDescriptor.FD_STDIN));
		cBuf.assemble("LEA ECX, [0x%x]".formatted(iov.getOffset()));
		cBuf.assemble("MOV EDX, 2");
		cBuf.assemble("INT 0x80");
		final Address captureAt = cBuf.getNext();
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		cBuf.assemble("MOV EBX, 0");
		cBuf.assemble("INT 0x80");
		cBuf.assemble("JMP 0x%x".formatted(cBuf.getNext().getOffset())); // Snuff JIT look-ahead
		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, cBuf.getBytes());
			block.putBytes(data, dBuf.array());
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		thread.inject(captureAt, "capture(EAX); emu_exec_decoded();");

		// Provide stdin via a byte array
		ByteArrayInputStream stdin = new ByteArrayInputStream(BYTES_HW);
		syscalls.putDescriptor(EmuUnixFileDescriptor.FD_STDIN,
			new IOStreamEmuUnixFileHandle(emu, program.getCompilerSpec(), stdin, null));
		execute(thread);

		assertEquals(List.of((long) BYTES_HW.length), capture.captured);
		assertArrayEquals(BYTES_HELLO, emu.getSharedState()
				.getVar(space, strHello.getOffset(), BYTES_HELLO.length, true, Reason.INSPECT));
		assertArrayEquals(BYTES_WORLD, emu.getSharedState()
				.getVar(space, strWorld.getOffset(), BYTES_WORLD.length, true, Reason.INSPECT));
	}

	@Test
	public void testReadvStdinErr() throws Exception {
		Address data = space.getAddress(0x00400800);

		ByteBuffer dBuf = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
		Address strHello = data.add(dBuf.position());
		dBuf.put(new byte[BYTES_HELLO.length]);
		Address endHello = data.add(dBuf.position());
		Address iov = data.add(dBuf.position());
		dBuf.putInt((int) strHello.getOffset());
		dBuf.putInt((int) endHello.subtract(strHello));
		int posIov1base = dBuf.position();
		dBuf.putInt(0);
		int posIov1len = dBuf.position();
		dBuf.putInt(0);
		Address strWorld = data.add(dBuf.position());
		dBuf.put(new byte[BYTES_WORLD.length]);
		Address endWorld = data.add(dBuf.position());
		// Backpatch
		dBuf.putInt(posIov1base, (int) strWorld.getOffset());
		dBuf.putInt(posIov1len, (int) endWorld.subtract(strWorld));

		AssemblyBuffer cBuf = new AssemblyBuffer(asm, start);
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.READV.number));
		cBuf.assemble("MOV EBX, %d".formatted(EmuUnixFileDescriptor.FD_STDIN));
		cBuf.assemble("LEA ECX, [0x%x]".formatted(iov.getOffset()));
		cBuf.assemble("MOV EDX, 2");
		cBuf.assemble("INT 0x80");
		final Address captureAt = cBuf.getNext();
		cBuf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		cBuf.assemble("MOV EBX, 0");
		cBuf.assemble("INT 0x80");
		cBuf.assemble("JMP 0x%x".formatted(cBuf.getNext().getOffset())); // Snuff JIT look-ahead
		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, cBuf.getBytes());
			block.putBytes(data, dBuf.array());
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		thread.inject(captureAt, "capture(EAX); emu_exec_decoded();");

		// DO NOT provide FD_STDIN, so that we get EBADF
		execute(thread);

		assertEquals(List.of((long) -9), capture.captured);
		assertArrayEquals(new byte[BYTES_HELLO.length], emu.getSharedState()
				.getVar(space, strHello.getOffset(), BYTES_HELLO.length, true, Reason.INSPECT));
		assertArrayEquals(new byte[BYTES_WORLD.length], emu.getSharedState()
				.getVar(space, strWorld.getOffset(), BYTES_WORLD.length, true, Reason.INSPECT));
	}

	@Test
	public void testOpenWriteClose() throws Exception {
		Address myFileAddr = space.getAddress(0x00400880);
		Address hwAddr = space.getAddress(0x00400800);
		AssemblyBuffer buf = new AssemblyBuffer(asm, start);

		buf.assemble("MOV EAX, %d".formatted(Syscall.OPEN.number));
		buf.assemble("LEA EBX, [0x%x]".formatted(myFileAddr.getOffset()));
		buf.assemble("MOV ECX, 0x%x".formatted(AbstractEmuLinuxSyscallUseropLibrary.O_WRONLY |
			AbstractEmuLinuxSyscallUseropLibrary.O_CREAT));
		buf.assemble("MOV EDX, 0x%x".formatted(0600));
		buf.assemble("INT 0x80");
		buf.assemble("MOV EBP, EAX");

		buf.assemble("MOV EAX, %d".formatted(Syscall.WRITE.number));
		buf.assemble("MOV EBX, EBP");
		buf.assemble("LEA ECX, [0x%x]".formatted(hwAddr.getOffset()));
		buf.assemble("MOV EDX, %d".formatted(BYTES_HW.length));
		buf.assemble("INT 0x80");

		buf.assemble("MOV EAX, %d".formatted(Syscall.CLOSE.number));
		buf.assemble("MOV EBX, EBP");
		buf.assemble("INT 0x80");

		buf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		buf.assemble("MOV EBX, 0");
		buf.assemble("INT 0x80");

		buf.assemble("JMP 0x%x".formatted(buf.getNext().getOffset())); // Snuff JIT look-ahead

		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, buf.getBytes());
			block.putBytes(hwAddr, BYTES_HW);
			block.putBytes(myFileAddr, "myfile\0".getBytes());
		}

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		EmuUnixFile<byte[]> file = fs.getFile("myfile");
		byte[] bytes = new byte[BYTES_HW.length];
		file.read(arithmetic, arithmetic.fromConst(0, 8), bytes);
		assertArrayEquals(BYTES_HW, bytes);
	}

	@Test
	public void testOpenReadClose() throws Exception {
		Address myFileAddr = space.getAddress(0x00400880);
		Address hwAddr = space.getAddress(0x00400800);
		AssemblyBuffer buf = new AssemblyBuffer(asm, start);

		buf.assemble("MOV EAX, %d".formatted(Syscall.OPEN.number));
		buf.assemble("LEA EBX, [0x%x]".formatted(myFileAddr.getOffset()));
		buf.assemble("MOV ECX, 0x%x".formatted(AbstractEmuLinuxSyscallUseropLibrary.O_RDONLY));
		buf.assemble("MOV EDX, 0x%x".formatted(0600));
		buf.assemble("INT 0x80");
		buf.assemble("MOV EBP, EAX");

		buf.assemble("MOV EAX, %d".formatted(Syscall.READ.number));
		buf.assemble("MOV EBX, EBP");
		buf.assemble("LEA ECX, [0x%x]".formatted(hwAddr.getOffset()));
		buf.assemble("MOV EDX, %d".formatted(BYTES_HW.length));
		buf.assemble("INT 0x80");

		buf.assemble("MOV EAX, %d".formatted(Syscall.CLOSE.number));
		buf.assemble("MOV EBX, EBP");
		buf.assemble("INT 0x80");

		buf.assemble("MOV EAX, %d".formatted(Syscall.EXIT.number));
		buf.assemble("MOV EBX, 0");
		buf.assemble("INT 0x80");

		buf.assemble("JMP 0x%x".formatted(buf.getNext().getOffset())); // Snuff JIT look-ahead

		try (Transaction _ = program.openTransaction("Initialize")) {
			block.putBytes(start, buf.getBytes());
			block.putBytes(myFileAddr, "myfile\0".getBytes());
		}

		EmuUnixFile<byte[]> file = fs.createOrGetFile("myfile", 0600);
		file.write(arithmetic, arithmetic.fromConst(0, 8), BYTES_HW);

		PcodeEmulator emu = prepareEmulator();
		PcodeThread<byte[]> thread = launchThread(emu, start);
		execute(thread);

		assertArrayEquals(BYTES_HW,
			emu.getSharedState().getVar(hwAddr, BYTES_HW.length, true, Reason.INSPECT));
	}
}
