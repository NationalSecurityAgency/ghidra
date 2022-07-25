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
/*
 * Created on Jun 12, 2003
 *
 * To change the template for this generated file go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * 
 *
 * Token representing an operation in C code text. This could be a keyword like
 * "if" or "while" but could also be an operator like '+' or '*'
 * The token may contain an id for the pcode object representing the operation
 */
public class ClangOpToken extends ClangToken {
	private PcodeOp op;

	public ClangOpToken(ClangNode par) {
		super(par);
		op = null;
	}

	@Override
	public PcodeOp getPcodeOp() {
		return op;
	}

	@Override
	public Address getMinAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}

	@Override
	public Address getMaxAddress() {
		if (op == null) {
			return null;
		}
		return op.getSeqnum().getTarget().getPhysicalAddress();
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws PcodeXMLException {
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_OPREF.id()) {
				int refid = (int) decoder.readUnsignedInteger();
				op = pfactory.getOpRef(refid);
			}
		}
		decoder.rewindAttributes();
		super.decode(decoder, pfactory);
	}
}
