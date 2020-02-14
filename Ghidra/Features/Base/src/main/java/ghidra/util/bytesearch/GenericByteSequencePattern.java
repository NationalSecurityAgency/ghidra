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
package ghidra.util.bytesearch;

import ghidra.program.model.data.DataType;

/**
 * Templated simple DittedBitSequence Pattern for a byte/mask pattern and associated action.
 * The DittedBitSequence is provided by value and mask in byte arrays.
 * 
 * This class is normally used to find some number of SequencePatterns within a seqence of bytes.
 * When the byte/mask pattern is matched, the GenericMatchAction will be "applied".
 *
 * @param <T> the class of match action, used to specify a specialized momento to be used by the action when it is "applied".
 */

public class GenericByteSequencePattern<T> extends Pattern {

	/**
	 * Construct a sequence of bytes with no mask, and associated action
	 * to be called if this pattern matches.
	 * 
	 * @param bytesSequence sequence of bytes to match
	 * @param action action to apply if the match succeeds
	 */
	public GenericByteSequencePattern(byte[] bytesSequence, GenericMatchAction<T> action) {
		super(new DittedBitSequence(bytesSequence), 0, new PostRule[0], new MatchAction[1]);

		MatchAction[] matchActions = getMatchActions();
		matchActions[0] = action;
	}

	/**
	 * Construct a sequence of bytes with a mask, and associated action
	 * to be called if this pattern matches.
	 * 
	 * @param bytesSequence sequence of bytes to match
	 * @param mask mask, bits that are 1 must match the byteSequence bits
	 * @param action to apply if the match succeeds
	 */
	public GenericByteSequencePattern(byte[] bytesSequence, byte[] mask,
			GenericMatchAction<DataType> action) {
		super(new DittedBitSequence(bytesSequence, mask), 0, new PostRule[0], new MatchAction[1]);

		MatchAction[] matchActions = getMatchActions();
		matchActions[0] = action;
	}
}
