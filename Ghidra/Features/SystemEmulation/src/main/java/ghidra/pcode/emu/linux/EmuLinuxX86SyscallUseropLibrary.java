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
import ghidra.framework.Application;
import ghidra.pcode.emu.DefaultPcodeThread.PcodeThreadExecutor;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.unix.EmuUnixFileSystem;
import ghidra.pcode.emu.unix.EmuUnixUser;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A system call library simulating Linux for x86 (32-bit)
 *
 * @param <T> the type of values processed by the library
 */
public class EmuLinuxX86SyscallUseropLibrary<T> extends AbstractEmuLinuxSyscallUseropLibrary<T> {
	protected final Register regEIP;
	protected final Register regEAX;

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
		regEIP = machine.getLanguage().getRegister("EIP");
		regEAX = machine.getLanguage().getRegister("EAX");
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

	@Override
	public long readSyscallNumber(PcodeExecutorState<T> state, Reason reason) {
		return machine.getArithmetic().toLong(state.getVar(regEAX, reason), Purpose.OTHER);
	}

	@Override
	protected boolean returnErrno(PcodeExecutor<T> executor, int errno) {
		executor.getState()
				.setVar(regEAX,
					executor.getArithmetic().fromConst(-errno, regEAX.getMinimumByteSize()));
		return true;
	}

	/**
	 * Implement this to detect and interpret the {@code INT 0x80} instruction as the syscall
	 * convention
	 * 
	 * @param executor to receive the executor
	 * @param library to receive the userop library, presumably replete with syscalls
	 * @param number the interrupt number
	 * @return the address of the fall-through, to hack the {@link PcodeOp#CALLIND}
	 */
	@PcodeUserop
	public T swi(@OpExecutor PcodeExecutor<T> executor, @OpLibrary PcodeUseropLibrary<T> library,
			T number) {
		PcodeArithmetic<T> arithmetic = executor.getArithmetic();
		long intNo = arithmetic.toLong(number, Purpose.OTHER);
		if (intNo == 0x80) {
			// A CALLIND follows to the return of swi().... OK.
			// We'll just make that "fall through" instead
			T next = executor.getState().getVar(regEIP, executor.getReason());
			PcodeThreadExecutor<T> te = (PcodeThreadExecutor<T>) executor;
			int pcSize = regEIP.getNumBytes();
			int iLen = te.getThread().getInstruction().getLength();
			next = arithmetic.binaryOp(PcodeOp.INT_ADD, pcSize, pcSize, next, pcSize,
				arithmetic.fromConst(iLen, pcSize));
			syscall(executor, library);
			return next;
		}
		throw new PcodeExecutionException("Unknown interrupt: 0x" + Long.toString(intNo, 16));
	}
}
