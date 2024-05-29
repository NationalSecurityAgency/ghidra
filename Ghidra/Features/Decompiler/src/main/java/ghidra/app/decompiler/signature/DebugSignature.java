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
package ghidra.app.decompiler.signature;

import static ghidra.program.model.pcode.ElementId.*;

import java.util.ArrayList;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A feature extracted from a function, with an additional description of what information is
 * incorporated into the feature.  The feature may incorporate data-flow and/or control-flow
 * information from the function. Internally, the feature is a 32-bit hash of this information, but
 * derived classes from this abstract class include more detailed information about how the hash was formed.
 */
public abstract class DebugSignature {
	public int hash;		// The underlying 32-bit hash of the feature

	/**
	 * Decode the feature from a stream.
	 * @param decoder is the stream decoder
	 * @throws DecoderException for problems reading the stream
	 */
	public abstract void decode(Decoder decoder) throws DecoderException;

	/**
	 * Write a brief description of this feature to the given StringBuffer.
	 * @param language is the underlying language of the function
	 * @param buf is the given StringBuffer
	 */
	public abstract void printRaw(Language language, StringBuffer buf);

	/**
	 * Decode an array of features from the stream. Collectively, the features make up
	 * a "feature vector" for a specific function.  Each feature is returned as a separate descriptive object.
	 * @param decoder is the stream decoder
	 * @param func is the specific function whose feature vector is being decoded
	 * @return the array of feature objects
	 * @throws DecoderException for problems reading from the stream
	 */
	public static ArrayList<DebugSignature> decodeSignatures(Decoder decoder, Function func)
			throws DecoderException {
		ArrayList<DebugSignature> res = new ArrayList<>();
		int el = decoder.openElement();
		int subel = decoder.peekElement();
		while (subel != 0) {
			DebugSignature sig;
			if (subel == ELEM_VARSIG.id()) {
				sig = new VarnodeSignature();
			}
			else if (subel == ELEM_BLOCKSIG.id()) {
				sig = new BlockSignature();
			}
			else if (subel == ELEM_COPYSIG.id()) {
				sig = new CopySignature();
			}
			else {
				throw new DecoderException("Unknown debug signature element");
			}
			sig.decode(decoder);
			res.add(sig);
			subel = decoder.peekElement();
		}
		decoder.closeElement(el);
		return res;
	}
}
