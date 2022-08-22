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
package ghidra.pcode.emu.sys;

import static ghidra.pcode.emu.sys.EmuSyscallLibrary.SYSCALL_CONVENTION_NAME;
import static ghidra.pcode.emu.sys.EmuSyscallLibrary.SYSCALL_SPACE_NAME;

import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

/**
 * Utilities for preparing a program for use in testing system call simulations
 */
public class SyscallTestHelper {
	/**
	 * A number-name pair defining a syscall
	 */
	public interface SyscallName {
		/**
		 * Get the system call number, i.e., its offset in "syscall"/OTHER space
		 * 
		 * @return the syscall number
		 */
		int getNumber();

		/**
		 * Get the system call name, i.e., its API name and the name used in the system call
		 * simulator's library
		 * 
		 * @return the syscall name
		 */
		String getName();
	}

	private final List<? extends SyscallName> names;

	/**
	 * Create a helper using the given list of system calls
	 * 
	 * @param names the number-name pairs for the system calls to support
	 */
	public SyscallTestHelper(List<? extends SyscallName> names) {
		this.names = names;
	}

	/**
	 * Prepare a program, simulating the analysis normally performed by the system call analyzer
	 * 
	 * @param program the program to prepare
	 * @throws Exception if something goes wrong
	 */
	public void bootstrapProgram(Program program) throws Exception {
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

		for (SyscallName n : names) {
			placeSyscall(program, n.getNumber(), n.getName());
		}
	}

	/**
	 * Place a system call function in the "syscall" overlay on OTHER
	 * 
	 * @param program the program with "syscall" space already create
	 * @param number the syscall number
	 * @param name the syscall name
	 * @throws Exception if something goes wrong
	 */
	protected void placeSyscall(Program program, long number, String name) throws Exception {
		AddressSpace spaceSyscall =
			program.getAddressFactory().getAddressSpace(SYSCALL_SPACE_NAME);
		FunctionManager functions = program.getFunctionManager();

		Address addr = spaceSyscall.getAddress(number);
		functions.createFunction(name, addr, new AddressSet(addr), SourceType.USER_DEFINED)
				.setCallingConvention(SYSCALL_CONVENTION_NAME);
	}
}
