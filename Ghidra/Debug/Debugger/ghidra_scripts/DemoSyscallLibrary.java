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
import java.nio.charset.Charset;
import java.util.Collection;

import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibrary;
import ghidra.pcode.emu.linux.EmuLinuxX86SyscallUseropLibrary;
import ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary;
import ghidra.pcode.emu.sys.EmuSyscallLibrary;
import ghidra.pcode.exec.*;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * A userop library that includes system call simulation
 * 
 * <p>
 * Such a library needs to implement {@link EmuSyscallLibrary}. Here we extend
 * {@link AnnotatedEmuSyscallUseropLibrary}, which allows us to implement it using annotated
 * methods. {@link EmuSyscallLibrary#syscall(PcodeExecutor, PcodeUseropLibrary)} is the system call
 * dispatcher, and it requires that each system call implement {@link EmuSyscallDefinition}. System
 * call libraries typically implement that interface by annotating p-code userops with
 * {@link EmuSyscall}. This allows system calls to be implemented via Java callback or Structured
 * Sleigh. Conventionally, the Java method names of system calls should be
 * <em>platform</em>_<em>name</em>. This is to prevent name-space pollution of userops.
 * 
 * <p>
 * Stock implementations for a limited set of Linux system calls are provided for x86 and amd64 in
 * {@link EmuLinuxX86SyscallUseropLibrary} and {@link EmuLinuxAmd64SyscallUseropLibrary},
 * respectively. The type hierarchy is designed to facilitate the implementation of related systems
 * without (too much) code duplication. Because they derive from the annotation-based
 * implementations, you can add missing system calls by extending one and adding annotated methods
 * as needed.
 * 
 * <p>
 * For demonstration, this will implement one from scratch for no particular operating system, but
 * it will borrow many conventions from linux-amd64.
 */
public class DemoSyscallLibrary extends AnnotatedEmuSyscallUseropLibrary<byte[]> {
	private final static Charset UTF8 = Charset.forName("utf8");

	// Implement all the required plumbing first:

	/**
	 * An exception type for "user errors." These errors should be communicated back to the target
	 * program rather than causing the emulator to interrupt. This is a bare minimum implementation.
	 * In practice more information should be communicated internally, in case things go further
	 * wrong. Also, a hierarchy of exceptions may be appropriate.
	 */
	static class UserError extends PcodeExecutionException {
		private final int errno;

		public UserError(int errno) {
			super("errno: " + errno);
			this.errno = errno;
		}
	}

	private final Register regRAX;
	private final GhidraScript script;

	/**
	 * Because the system call numbering is derived from the "syscall" overlay on OTHER space, a
	 * program is required. The system call analyzer must be applied to it. The program and its
	 * compiler spec are also used to derive (what it can of) the system call ABI. Notably, it
	 * applies the calling convention of the functions placed in syscall overlay. Those parts which
	 * cannot (yet) be derived from the program are instead implemented as abstract methods of this
	 * class, e.g., {@link #readSyscallNumber(PcodeExecutorStatePiece)} and
	 * {@link #handleError(PcodeExecutor, PcodeExecutionException)}.
	 * 
	 * @param machine the emulator
	 * @param program the program being emulated
	 */
	public DemoSyscallLibrary(PcodeMachine<byte[]> machine, Program program, GhidraScript script) {
		super(machine, program);
		this.script = script;
		this.regRAX = machine.getLanguage().getRegister("RAX");
		if (regRAX == null) {
			throw new AssertionError("This library only works on x64 targets");
		}
	}

	/**
	 * The dispatcher doesn't know where the system call number is stored. It relies on this method
	 * to read that number from the state. Here we'll assume the target is x64 and RAX contains the
	 * syscall number.
	 */
	@Override
	public long readSyscallNumber(PcodeExecutorStatePiece<byte[], byte[]> state) {
		return Utils.bytesToLong(state.getVar(regRAX), regRAX.getNumBytes(),
			machine.getLanguage().isBigEndian());
	}

	/**
	 * If the error is a user error, put the errno into the machine as expected by the target
	 * program. Here we negate the errno and put it into RAX. If it's not a user error, we return
	 * false letting the dispatcher know it should interrupt the emulator.
	 */
	@Override
	public boolean handleError(PcodeExecutor<byte[]> executor, PcodeExecutionException err) {
		if (err instanceof UserError) {
			executor.getState()
					.setVar(regRAX, executor.getArithmetic()
							.fromConst(-((UserError) err).errno, regRAX.getNumBytes()));
			return true;
		}
		return false;
	}

	/**
	 * Support for Structured Sleigh is built-in. To enable it, override this method and instantiate
	 * the appropriate (usually nested) class.
	 */
	@Override
	protected StructuredPart newStructuredPart() {
		return new DemoStructuredPart();
	}

	@Override
	protected Collection<DataTypeManager> getAdditionalArchives() {
		// Add platform-specific data type archives, if needed
		return super.getAdditionalArchives();
	}

	// Now, implement some system calls!

	// First, a Java callback example

	/**
	 * Write a buffer of utf-8 characters to the console
	 * 
	 * <p>
	 * The {@link EmuSyscall} annotation allows us to specify the system call name, because the
	 * userop name should be prefixed with the platform name, to avoid naming collisions among
	 * userops.
	 * 
	 * <p>
	 * For demonstration, we will export this as a system call, though that is not required for
	 * {@link DemoStructuredPart#demo_console(StructuredSleigh.Var)} to invoke it. It does need to
	 * be a userop, but it doesn't need to be a syscall.
	 * 
	 * @param str a pointer to the start of the buffer
	 * @param end a pointer to the end (exclusive) of the buffer
	 */
	@PcodeUserop
	@EmuSyscall("write")
	public void demo_write(byte[] str, byte[] end) {
		AddressSpace space = machine.getLanguage().getDefaultSpace();
		/**
		 * Because we have concrete {@code byte[]}, we could use Utils.bytesToLong, but for
		 * demonstration, here's how it can be done if we extended
		 * {@link AnnotatedEmuSyscallUseropLibrary}{@code <T>} instead. If the value cannot be made
		 * concrete, an exception will be thrown. For abstract types, it's a good idea to save a
		 * copy of the arithmetic as a field at library construction time.
		 */
		PcodeArithmetic<byte[]> arithmetic = machine.getArithmetic();
		long strLong = arithmetic.toConcrete(str).longValue();
		long endLong = arithmetic.toConcrete(end).longValue();

		byte[] stringBytes =
			machine.getSharedState().getVar(space, strLong, (int) (endLong - strLong), true);
		String string = new String(stringBytes, UTF8);
		script.println(string);
	}

	// Second, a Structured Sleigh example

	/**
	 * The nested class for syscall implemented using StructuredSleigh. Note that no matter the
	 * implementation type, the Java method is annotated with {@link EmuSyscall}. We declare it
	 * public so that the annotation processor can access the methods. Alternatively, we could
	 * override {@link #getMethodLookup()}.
	 */
	public class DemoStructuredPart extends StructuredPart {
		UseropDecl write = userop(type("void"), "demo_write", types("char *", "char *"));

		/**
		 * Write a C-style string to the console
		 * 
		 * @param str the null-terminated utf-8 string
		 */
		@StructuredUserop
		@EmuSyscall("console")
		public void demo_console(@Param(type = "char *") Var str) {
			// Measure the string's length and then invoke write
			Var end = local("end", type("char *"));
			_for(end.set(str), end.deref().neq(0), end.inc(), () -> {
			});
			write.call(str, end);
		}
	}
}
