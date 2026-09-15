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
package ghidra.pcode.emu.symz3.lib;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibrary;
import ghidra.pcode.emu.unix.EmuUnixFileSystem;
import ghidra.pcode.emu.unix.EmuUnixUser;
import ghidra.program.model.listing.Program;
import ghidra.symz3.model.SymValueZ3;

/**
 * A library for the Symbolic Summary Z3 should we wish to customize any functions
 * 
 * <p>
 * This library is not currently accessible from the UI. It can be used with scripts by overriding a
 * emulator's userop library factory method.
 * 
 * <p>
 * TODO: A means of adding and configuring userop libraries in the UI.
 * 
 * <p>
 * TODO: Example scripts.
 */
public class SymZ3LinuxAmd64SyscallLibrary
		extends EmuLinuxAmd64SyscallUseropLibrary<Pair<byte[], SymValueZ3>> {

	public SymZ3LinuxAmd64SyscallLibrary(PcodeMachine<Pair<byte[], SymValueZ3>> machine,
			EmuUnixFileSystem<Pair<byte[], SymValueZ3>> fs, Program program, EmuUnixUser user) {
		super(machine, fs, program, user);
	}

	public SymZ3LinuxAmd64SyscallLibrary(PcodeMachine<Pair<byte[], SymValueZ3>> machine,
			EmuUnixFileSystem<Pair<byte[], SymValueZ3>> fs, Program program) {
		super(machine, fs, program);
	}
}
