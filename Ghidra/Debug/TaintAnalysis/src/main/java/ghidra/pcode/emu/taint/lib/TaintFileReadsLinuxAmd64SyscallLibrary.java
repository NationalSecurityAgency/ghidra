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
package ghidra.pcode.emu.taint.lib;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.linux.EmuLinuxAmd64SyscallUseropLibrary;
import ghidra.pcode.emu.unix.EmuUnixFileSystem;
import ghidra.pcode.emu.unix.EmuUnixUser;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.listing.Program;
import ghidra.taint.model.TaintVec;

/**
 * A library for performing Taint Analysis on a Linux-amd64 program that reads from tainted files
 * 
 * <p>
 * This library is not currently accessible from the UI. It can be used with scripts by overriding a
 * taint emulator's userop library factory method.
 * 
 * <p>
 * TODO: A means of adding and configuring userop libraries in the UI.
 * 
 * <p>
 * TODO: Example scripts.
 */
public class TaintFileReadsLinuxAmd64SyscallLibrary
		extends EmuLinuxAmd64SyscallUseropLibrary<Pair<byte[], TaintVec>> {

	public TaintFileReadsLinuxAmd64SyscallLibrary(PcodeMachine<Pair<byte[], TaintVec>> machine,
			EmuUnixFileSystem<Pair<byte[], TaintVec>> fs, Program program, EmuUnixUser user) {
		super(machine, fs, program, user);
	}

	public TaintFileReadsLinuxAmd64SyscallLibrary(PcodeMachine<Pair<byte[], TaintVec>> machine,
			EmuUnixFileSystem<Pair<byte[], TaintVec>> fs, Program program) {
		super(machine, fs, program);
	}

	@Override
	public Pair<byte[], TaintVec> unix_read(PcodeExecutorState<Pair<byte[], TaintVec>> state,
			Pair<byte[], TaintVec> fd, Pair<byte[], TaintVec> bufPtr,
			Pair<byte[], TaintVec> count) {

		Pair<byte[], TaintVec> result = super.unix_read(state, fd, bufPtr, count);

		TaintVec taintResult = result.getRight();
		// TODO: Some representation of a "min" function. For now, just mix everything
		taintResult = TaintVec.copies(taintResult.union().union(count.getRight().union()),
			taintResult.length);
		// TODO: This seems to make sense, but maybe a different tag?
		//   We're "reading" the size field from a table lookup, keyed by fd
		taintResult = taintResult.tagIndirectRead(fd.getRight());

		// TODO: Should I taint the output buffer with the file descriptor? Meh.
		return Pair.of(result.getLeft(), taintResult);
	}
}
