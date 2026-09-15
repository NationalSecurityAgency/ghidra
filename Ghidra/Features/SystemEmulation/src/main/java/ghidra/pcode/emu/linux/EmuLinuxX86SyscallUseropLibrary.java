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

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.util.PseudoInstruction;
import ghidra.framework.Application;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.jit.decode.CanDecode;
import ghidra.pcode.emu.unix.EmuUnixFileSystem;
import ghidra.pcode.emu.unix.EmuUnixUser;
import ghidra.pcode.exec.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;

/**
 * A system call library simulating Linux for x86 (32-bit)
 *
 * @param <T> the type of values processed by the library
 */
public class EmuLinuxX86SyscallUseropLibrary<T> extends AbstractEmuLinuxSyscallUseropLibrary<T> {

	protected FileDataTypeManager clib32;

	/**
	 * Construct the system call library for Linux-x86
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing syscall definitions and conventions, likely the target
	 *            program
	 */
	public EmuLinuxX86SyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program) {
		this(machine, fs, program, EmuUnixUser.DEFAULT_USER);
	}

	/**
	 * Construct the system call library for Linux-x86
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing syscall definitions and conventions, likely the target
	 *            program
	 * @param user the "current user" to simulate
	 */
	public EmuLinuxX86SyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program, EmuUnixUser user) {
		super(machine, fs, program, user);
	}

	@Override
	protected Collection<DataTypeManager> getAdditionalArchives() {
		try {
			ResourceFile file =
				Application.findDataFileInAnyModule("typeinfo/generic/generic_clib.gdt");
			clib32 = FileDataTypeManager.openFileArchive(file, false);
			return List.of(clib32);
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void disposeAdditionalArchives() {
		clib32.close();
	}

	/**
	 * Implement this to detect and interpret the {@code INT 0x80} instruction as the syscall
	 * convention
	 * 
	 * @param executor to receive the executor
	 * @param library to receive the userop library, presumably replete with syscalls
	 * @param out the output varnode
	 * @param intNo the interrupt number
	 */
	@PcodeUserop(canInline = true)
	public void swi(@OpExecutor PcodeExecutor<T> executor, @OpLibrary PcodeUseropLibrary<T> library,
			@OpOutput Varnode out, int intNo) {
		// A CALLIND follows to the return of swi().... OK.
		// We'll just cause that to "fall through" instead
		// Thus, we need the instruction, and we must compile invocation-specific p-code
		if (intNo == 0x80) {
			if (!(executor instanceof CanDecode decoder)) {
				throw new PcodeExecutionException(
					"Cannot interpret swi(0x80) without the instruction decoder");
			}
			PseudoInstruction instruction = decoder.decodeInstruction();
			Address next = instruction.getAddress().add(instruction.getLength());
			PcodeProgram prog =
				SleighProgramCompiler.compileUserop(executor.getLanguage(), "swi",
					List.of(SleighPcodeUseropDefinition.OUT_SYMBOL_NAME), """
							EAX = emu_syscall(EAX);
							%s = 0x%x;
							""".formatted(
						SleighPcodeUseropDefinition.OUT_SYMBOL_NAME, next.getOffset()),
					library, List.of(out));
			executor.execute(prog, library);
		}
		else {
			throw new PcodeExecutionException("Unknown interrupt: 0x%x".formatted(intNo));
		}
	}
}
