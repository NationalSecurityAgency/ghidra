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
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.*;

/**
 * A source code token representing a control-flow label.
 */
public class ClangLabelToken extends ClangToken {
	private Address blockaddr;	// Address this is labeling

	public ClangLabelToken(ClangNode par) {
		super(par);
		blockaddr = null;
	}

	@Override
	public boolean isVariableRef() {
		return false;
	}

	@Override
	public Address getMinAddress() {
		return blockaddr;
	}

	@Override
	public Address getMaxAddress() {
		return blockaddr;
	}

	@Override
	public void decode(Decoder decoder, PcodeFactory pfactory) throws DecoderException {
		AddressSpace spc = decoder.readSpace(AttributeId.ATTRIB_SPACE);
		long offset = decoder.readUnsignedInteger(AttributeId.ATTRIB_OFF);
		blockaddr = spc.getAddress(offset);
		super.decode(decoder, pfactory);
	}

}
