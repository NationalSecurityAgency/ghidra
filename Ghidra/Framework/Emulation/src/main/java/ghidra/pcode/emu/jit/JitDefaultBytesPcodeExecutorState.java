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

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.analysis.JitDataFlowState;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.DefaultPcodeExecutorState;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * The default implementation of {@link JitBytesPcodeExecutorState}.
 * 
 * <p>
 * <b>NOTE</b>: This is distinct from {@link JitDataFlowState}, which is used during the
 * interpretation and analysis of the passage to translate. This state, in contrast, is the concrete
 * state of the emulation target, but accessible in special ways to the translation output. In
 * particular, the constructor of each translation is permitted direct access to some of this
 * state's internals, so that it can pre-fetch, e.g., backing arrays for direct memory access
 * operations.
 * 
 * <p>
 * This is just an extension of {@link DefaultPcodeExecutorState} that wraps the corresponding
 * {@link JitBytesPcodeExecutorStatePiece}.
 */
public class JitDefaultBytesPcodeExecutorState extends DefaultPcodeExecutorState<byte[]>
		implements JitBytesPcodeExecutorState {

	/**
	 * Construct a new state for the given language
	 * 
	 * @param language the emulation target language
	 */
	public JitDefaultBytesPcodeExecutorState(Language language) {
		super(new JitBytesPcodeExecutorStatePiece(language),
			BytesPcodeArithmetic.forLanguage(language));
	}

	/**
	 * Get the piece cast to the type we know it is
	 * 
	 * @return the piece
	 */
	protected JitBytesPcodeExecutorStatePiece getPiece() {
		return (JitBytesPcodeExecutorStatePiece) this.piece;
	}

	@Override
	public JitBytesPcodeExecutorStateSpace getForSpace(AddressSpace space) {
		return getPiece().getForSpace(space, true);
	}
}
