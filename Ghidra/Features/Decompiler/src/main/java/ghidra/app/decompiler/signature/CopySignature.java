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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A feature representing 1 or more "stand-alone" copies in a basic block.
 * A COPY operation is considered stand-alone if either a constant or a function input
 * is copied into a location that is then not read directly by the function.
 * These COPYs are incorporated into a single feature, which encodes the number
 * and type of COPYs but does not encode the order in which they occur within the block.
 */
public class CopySignature extends DebugSignature {
	public int index;						// The basic block's index 

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_COPYSIG);
		hash = (int) decoder.readUnsignedInteger(ATTRIB_HASH);
		index = (int) decoder.readSignedInteger(ATTRIB_INDEX);
		decoder.closeElement(el);
	}

	@Override
	public void printRaw(Language language, StringBuffer buf) {
		buf.append(Integer.toHexString(hash));
		buf.append(" - Copies in block ");
		buf.append(index);
	}

}
