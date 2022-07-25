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
package ghidra.program.model.pcode;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;

public class HighLocal extends HighVariable {

	private Address pcaddr; 	// null or Address of PcodeOp which defines the representative
	private HighSymbol symbol;

	/**
	 * Constructor for use with restoreXml
	 * @param high is the HighFunction containing this local variable
	 */
	public HighLocal(HighFunction high) {
		super(high);
	}

	public HighLocal(DataType type, Varnode vn, Varnode[] inst, Address pc, HighSymbol sym) {
		super(sym.getName(), type, vn, inst, sym.getHighFunction());
		pcaddr = pc;
		symbol = sym;
	}

	@Override
	public HighSymbol getSymbol() {
		return symbol;
	}

	/**
	 * @return instruction address the variable comes into scope within the function
	 */
	public Address getPCAddress() {
		return pcaddr;
	}

	@Override
	public void decode(Decoder decoder) throws PcodeXMLException {
		//int el = decoder.openElement(ElementId.ELEM_HIGH);
		long symref = decoder.readUnsignedInteger(AttributeId.ATTRIB_SYMREF);
		offset = -1;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_OFFSET.id()) {
				offset = (int) decoder.readUnsignedInteger();
				break;
			}
		}
		decodeInstances(decoder);
		symbol = function.getLocalSymbolMap().getSymbol(symref);
		if (symbol == null) {
			throw new PcodeXMLException("HighLocal is missing symbol");
		}
		if (offset < 0) {
			name = symbol.getName();
		}
		else {
			name = "UNNAMED";
		}
		pcaddr = symbol.getPCAddress();
		symbol.setHighVariable(this);

		//decoder.closeElement(el);
	}

}
