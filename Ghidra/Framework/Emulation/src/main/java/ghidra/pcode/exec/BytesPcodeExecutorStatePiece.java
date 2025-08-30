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

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * A plain concrete state piece without any backing objects
 */
public class BytesPcodeExecutorStatePiece
		extends AbstractBytesPcodeExecutorStatePiece<BytesPcodeExecutorStateSpace> {

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language (used for its memory model)
	 * @param cb callbacks to receive emulation events
	 */
	public BytesPcodeExecutorStatePiece(Language language, PcodeStateCallbacks cb) {
		super(language, cb);
	}

	@Override
	public BytesPcodeExecutorStatePiece fork(PcodeStateCallbacks cb) {
		BytesPcodeExecutorStatePiece result = new BytesPcodeExecutorStatePiece(language, cb);
		forkMap(result.spaceMap, this.spaceMap, s -> s.fork(result));
		return result;
	}

	@Override
	protected BytesPcodeExecutorStateSpace newSpace(AddressSpace space) {
		return new BytesPcodeExecutorStateSpace(language, space, this);
	}
}
