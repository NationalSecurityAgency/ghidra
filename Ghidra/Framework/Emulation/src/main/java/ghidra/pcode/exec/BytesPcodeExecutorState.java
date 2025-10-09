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
package ghidra.pcode.exec;

import ghidra.program.model.lang.Language;

/**
 * A state composing a single {@link BytesPcodeExecutorStatePiece}
 */
public class BytesPcodeExecutorState extends DefaultPcodeExecutorState<byte[]> {
	/**
	 * Create the state
	 * 
	 * @param language the language (processor model)
	 * @param cb callbacks to receive emulation events
	 */
	public BytesPcodeExecutorState(Language language, PcodeStateCallbacks cb) {
		super(new BytesPcodeExecutorStatePiece(language, cb));
	}

	protected BytesPcodeExecutorState(PcodeExecutorStatePiece<byte[], byte[]> piece) {
		super(piece);
	}

	@Override
	public BytesPcodeExecutorState fork(PcodeStateCallbacks cb) {
		return new BytesPcodeExecutorState(piece.fork(cb));
	}
}
