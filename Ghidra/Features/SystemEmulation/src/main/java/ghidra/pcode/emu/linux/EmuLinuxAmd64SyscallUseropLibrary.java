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
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.unix.EmuUnixFileSystem;
import ghidra.pcode.emu.unix.EmuUnixUser;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * A system call library simulating Linux for amd64 / x86_64
 *
 * @param <T> the type of values processed by the library
 */
public class EmuLinuxAmd64SyscallUseropLibrary<T> extends AbstractEmuLinuxSyscallUseropLibrary<T> {

	protected final Register regRAX;

	protected FileDataTypeManager clib64;

	/**
	 * Construct the system call library for Linux-amd64
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing syscall definitions and conventions, likely the target
	 *            program
	 */
	public EmuLinuxAmd64SyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program) {
		super(machine, fs, program);
		regRAX = machine.getLanguage().getRegister("RAX");
	}

	/**
	 * Construct the system call library for Linux-amd64
	 * 
	 * @param machine the machine emulating the hardware
	 * @param fs the file system to export to the user-space program
	 * @param program a program containing syscall definitions and conventions, likely the target
	 *            program
	 * @param user the "current user" to simulate
	 */
	public EmuLinuxAmd64SyscallUseropLibrary(PcodeMachine<T> machine, EmuUnixFileSystem<T> fs,
			Program program, EmuUnixUser user) {
		super(machine, fs, program, user);
		regRAX = machine.getLanguage().getRegister("RAX");
	}

	@Override
	protected Collection<DataTypeManager> getAdditionalArchives() {
		try {
			ResourceFile file =
				Application.findDataFileInAnyModule("typeinfo/generic/generic_clib_64.gdt");
			clib64 = FileDataTypeManager.openFileArchive(file, false);
			return List.of(clib64);
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	protected void disposeAdditionalArchives() {
		clib64.close();
	}

	@Override
	public long readSyscallNumber(PcodeExecutorState<T> state, Reason reason) {
		return machine.getArithmetic().toLong(state.getVar(regRAX, reason), Purpose.OTHER);
	}

	@Override
	protected boolean returnErrno(PcodeExecutor<T> executor, int errno) {
		executor.getState()
				.setVar(regRAX,
					executor.getArithmetic().fromConst(-errno, regRAX.getMinimumByteSize()));
		return true;
	}
}
