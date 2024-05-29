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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.*;

/**
 * A feature rooted in a basic block.  There are two forms of a block feature.
 * Form 1 contains only local control-flow information about the basic block.
 * Form 2 is a feature that combines two operations that occur in sequence within the block.
 * This form incorporates info about the operations and data-flow info about their inputs. 
 */
public class BlockSignature extends DebugSignature {
	public Address blockSeq;				// Address of the (start of) the basic block producing this signature
	public int index;						// The basic block's index 
	public SequenceNumber opSeq;			// Address of the primary operation producing this signature
	public String opcode;					// Op-code of the primary operation
	public SequenceNumber previousOpSeq;	// Address of root operation previous to primary
	public String previousOpcode;			// Op-code of the previous operation

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		opSeq = null;
		opcode = null;
		previousOpcode = null;
		previousOpSeq = null;
		int pos = 0;
		int el = decoder.openElement();
		hash = (int) decoder.readUnsignedInteger(ATTRIB_HASH);
		index = (int) decoder.readSignedInteger(ATTRIB_INDEX);
		blockSeq = AddressXML.decode(decoder);
		for (;;) {
			int subel = decoder.openElement();
			if (subel == 0) {
				break;
			}
			int opc = (int) decoder.readSignedInteger(ATTRIB_CODE);
			String currentOpcode = PcodeOp.getMnemonic(opc);
			SequenceNumber currentOpSeq = SequenceNumber.decode(decoder);
			decoder.closeElementSkipping(subel);
			if (pos == 0) {
				opSeq = currentOpSeq;
				opcode = currentOpcode;
			}
			else {
				previousOpSeq = currentOpSeq;
				previousOpcode = currentOpcode;
			}
			pos += 1;
		}
		decoder.closeElement(el);
	}

	@Override
	public void printRaw(Language language, StringBuffer buf) {
		buf.append(Integer.toHexString(hash));
		buf.append(" - block ");
		buf.append(blockSeq.toString());
		if (previousOpcode != null) {
			buf.append(" - op=");
			buf.append(previousOpcode).append(" ").append(previousOpSeq.toString());
		}
		if (opcode != null) {
			buf.append(" - op=");
			buf.append(opcode).append(" ").append(opSeq.toString());
		}
	}
}
