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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.*;

/**
 * A feature representing a portion of the data-flow graph rooted at a particular Varnode.
 * The feature recursively incorporates details about the Varnode, the operation that defined it, and
 * the operation's input Varnodes, up to a specific depth.
 */
public class VarnodeSignature extends DebugSignature {
	public Varnode vn;				// Root of the data-flow feature
	public SequenceNumber seqNum;	// The sequence number of the operation defining the root (may be null)
	public String opcode;			// The name of the defining operation (may be null)

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_VARSIG);
		hash = (int) decoder.readUnsignedInteger(ATTRIB_HASH);
		int subel = decoder.openElement();
		Address vnAddr = AddressXML.decodeFromAttributes(decoder);
		int vnSize = 0;
		if (vnAddr.getAddressSpace().isVariableSpace()) {
			//varnodes in the variable space will have a default offset of -1
			//but we can get the correct size
			decoder.rewindAttributes();
			Varnode.Join join = Varnode.decodePieces(decoder);
			vnSize = join.logicalSize;
		}
		else {
			vnSize = (int) decoder.readSignedInteger(ATTRIB_SIZE);
		}
		vn = new Varnode(vnAddr, vnSize);
		decoder.closeElement(subel);
		if (decoder.peekElement() != 0) {
			subel = decoder.openElement();
			int opc = (int) decoder.readSignedInteger(ATTRIB_CODE);
			opcode = PcodeOp.getMnemonic(opc);
			seqNum = SequenceNumber.decode(decoder);
			decoder.closeElementSkipping(subel);	// Skip the input/output varnodes
		}
		else {
			seqNum = null;
			opcode = null;
		}
		decoder.closeElement(el);
	}

	@Override
	public void printRaw(Language language, StringBuffer buf) {
		buf.append(Integer.toHexString(hash));
		buf.append(" - var ");
		buf.append(vn.toString(language));
		if (seqNum != null) {
			buf.append(" - op=");
			buf.append(opcode).append(" ").append(seqNum.toString());
		}
	}
}
