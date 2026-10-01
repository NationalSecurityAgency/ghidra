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
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.BuilderStage1;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;

/**
 * A userop library that includes system call simulation
 * <p>
 * Such a library needs to implement {@link EmuSyscallLibrary}. Here we extend
 * {@link AnnotatedEmuSyscallUseropLibrary}, which allows us to implement it using annotated
 * methods. {@link EmuSyscallLibrary#emu_syscall} is the system call dispatcher, and it requires
 * that each system call implement
 * {@link ghidra.pcode.emu.sys.EmuSyscallLibrary.EmuSyscallDefinition}. System call libraries
 * typically implement that interface by annotating p-code userops with
 * {@link ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary.EmuSyscall}. This allows system
 * calls to be implemented via Java callback or Sleigh. Conventionally, the Java method names of
 * system calls should be <em>platform</em>_<em>name</em>. This is to prevent name conflicts among
 * userops when several libraries are composed.
 * <p>
 * Stock implementations for a limited set of Linux system calls are provided for x86 and amd64 in
 * {@link EmuLinuxX86SyscallUseropLibrary} and {@link EmuLinuxAmd64SyscallUseropLibrary},
 * respectively. The type hierarchy is designed to facilitate the implementation of related systems
 * without (too much) code duplication. Because they derive from the annotation-based
 * implementations, you can add missing system calls by extending one and adding annotated methods
 * as needed.
 * <p>
 * For demonstration, this will implement one from scratch for no particular operating system, but
 * it will borrow many conventions from Linux-amd64.
 */
public class DemoSyscallLibrary extends AnnotatedEmuSyscallUseropLibrary<byte[]> {
	private final static Charset UTF8 = Charset.forName("utf8");

	private final GhidraScript script;

	/**
	 * Because the system call numbering is derived from the "syscall" overlay on OTHER space, a
	 * program is required. Use the system call analyzer on your program to populate this space. The
	 * program and its compiler spec are also used to derive (what it can of) the system call ABI.
	 * Notably, it applies the calling convention of the functions placed in the syscall overlay.
	 * 
	 * @param machine the emulator
	 * @param program the program being emulated
	 * @param script the script
	 */
	public DemoSyscallLibrary(PcodeMachine<byte[]> machine, Program program, GhidraScript script) {
		super(machine, program);
		this.script = script;
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
	 * <p>
	 * The {@link ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary.EmuSyscall} annotation
	 * allows us to specify the system call name, because the userop name should be prefixed with
	 * the platform name, to avoid naming collisions among composed libraries.
	 * <p>
	 * For demonstration, we will export this as a system call, though that is not required for
	 * {@link DemoStructuredPart#demo_console(StructuredSleigh.Var)} to invoke it. It does need to
	 * be a userop, but it doesn't need to be a syscall.
	 * 
	 * @param executor the emulator's underlying p-code executor
	 * @param str a pointer to the start of the buffer
	 * @param end a pointer to the end (exclusive) of the buffer
	 * @implNote Because we have concrete {@code byte[]}, we could use {@link Utils#bytesToLong},
	 *           but for demonstration, here's how it can be done if we extended
	 *           {@link AnnotatedEmuSyscallUseropLibrary}{@code <T>} instead. If the value cannot be
	 *           made concrete, an exception will be thrown. For abstract types, it's a good idea to
	 *           save a copy of the arithmetic as a field at library construction time.
	 */
	@PcodeUserop
	@EmuSyscall("write")
	public void demo_write(@OpExecutor PcodeExecutor<byte[]> executor, byte[] str, byte[] end) {
		AddressSpace space = machine.getLanguage().getDefaultSpace();
		PcodeArithmetic<byte[]> arithmetic = machine.getArithmetic();
		long strLong = arithmetic.toLong(str, Purpose.LOAD);
		long endLong = arithmetic.toLong(end, Purpose.OTHER);

		byte[] stringBytes = machine.getSharedState()
				.getVar(space, strLong, (int) (endLong - strLong), true, executor.getReason());
		String string = new String(stringBytes, UTF8);
		script.println(string);
	}

	// Second, a Structured Sleigh example

	/**
	 * The nested class for syscalls implemented using Structured Sleigh. Note that no matter the
	 * implementation type, the Java method is annotated with
	 * {@link ghidra.pcode.emu.sys.AnnotatedEmuSyscallUseropLibrary.EmuSyscall}. We declare the
	 * class public so that the annotation processor can access the methods. Alternatively, we could
	 * override {@link #getMethodLookup()} to provide the processor private access.
	 */
	public class DemoStructuredPart extends StructuredPart {
		/**
		 * This creates a handle to the "demo_write" p-code userop for use in Structured Sleigh.
		 * Otherwise, there's no way to refer to the userop. Think of it like a "forward" or
		 * "external" declaration.
		 */
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

	// Finally, the actual syscall userop, which we implement in plain Sleigh.

	@PcodeUserop
	public SleighPcodeUseropDefinition syscall(BuilderStage1 builder) {
		return builder.params().body(_ -> """
				RAX = emu_syscall(RAX);
				""").build();
	}
}
