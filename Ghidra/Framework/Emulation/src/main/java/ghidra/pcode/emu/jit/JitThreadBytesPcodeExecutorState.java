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
package ghidra.pcode.emu.jit;

import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.program.model.address.AddressSpace;

/**
 * The equivalent to {@link ThreadPcodeExecutorState} that multiplexes shared and local state for
 * the JIT-accelerated p-code emulator
 */
public class JitThreadBytesPcodeExecutorState extends ThreadPcodeExecutorState<byte[]>
		implements JitBytesPcodeExecutorState {

	/**
	 * Construct a new thread state
	 * 
	 * @param sharedState the shared portion (e.g., ram space)
	 * @param localState the local portion (i.e., register, unique spaces)
	 */
	public JitThreadBytesPcodeExecutorState(JitDefaultBytesPcodeExecutorState sharedState,
			JitDefaultBytesPcodeExecutorState localState) {
		super(sharedState, localState);
	}

	@Override
	public JitDefaultBytesPcodeExecutorState getSharedState() {
		return (JitDefaultBytesPcodeExecutorState) super.getSharedState();
	}

	@Override
	public JitDefaultBytesPcodeExecutorState getLocalState() {
		return (JitDefaultBytesPcodeExecutorState) super.getLocalState();
	}

	@Override
	public JitBytesPcodeExecutorStateSpace getForSpace(AddressSpace space) {
		if (isThreadLocalSpace(space)) {
			return getLocalState().getForSpace(space);
		}
		return getSharedState().getForSpace(space);
	}
}
