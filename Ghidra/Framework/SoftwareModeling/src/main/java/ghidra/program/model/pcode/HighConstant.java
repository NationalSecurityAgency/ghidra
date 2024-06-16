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
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

/**
 * 
 *
 * A constant that has been given a datatype (like a constant that is really a pointer)
 */
public class HighConstant extends HighVariable {

	private HighSymbol symbol;
	private Address pcaddr;		// null or Address of PcodeOp which defines the representative

	/**
	 * Constructor for use with restoreXml
	 * @param func is the HighFunction this constant belongs to
	 */
	public HighConstant(HighFunction func) {
		super(func);
	}

	/**
	 * Construct a constant NOT associated with a symbol
	 * @param name name of variable
	 * @param type data type of variable
	 * @param vn constant varnode
	 * @param pc code unit address where constant is used
	 * @param func the associated high function
	 */
	public HighConstant(String name, DataType type, Varnode vn, Address pc, HighFunction func) {
		super(name, type, vn, null, func);
		pcaddr = pc;
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

	/**
	 * @return constant as a scalar object
	 */
	public Scalar getScalar() {
		boolean signed = false;
		long value = getRepresentative().getOffset();
		DataType dt = getDataType();
		if (dt instanceof AbstractIntegerDataType) {
			signed = ((AbstractIntegerDataType) dt).isSigned();
		}
		if (signed) {
			// force sign extension of value
			int bitLength = getSize() * 8;
			int shiftCnt = 64 - bitLength;
			value <<= shiftCnt;
			value >>= shiftCnt;
		}
		return new Scalar(getSize() * 8, value, signed);
	}

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		//int el = decoder.openElement(ElementId.ELEM_HIGH);
		long symref = 0;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == AttributeId.ATTRIB_SYMREF.id()) {
				symref = decoder.readUnsignedInteger();
			}
		}
		decodeInstances(decoder);
		pcaddr = function.getPCAddress(represent);
		if (symref != 0) {
			symbol = function.getLocalSymbolMap().getSymbol(symref);
			if (symbol == null) {
				symbol = function.getGlobalSymbolMap().getSymbol(symref);
			}
			if (symbol == null) {
				GlobalSymbolMap globalMap = function.getGlobalSymbolMap();
				Program program = function.getFunction().getProgram();
				symbol = globalMap.populateSymbol(symref, null, -1);
				if (symbol == null) {
					PcodeOp op = ((VarnodeAST) represent).getLoneDescend();
					Address addr = HighFunctionDBUtil
							.getSpacebaseReferenceAddress(program.getAddressFactory(), op);
					if (addr != null) {
						Data data = program.getListing().getDataAt(addr);
						DataType dt = data == null ? DataType.DEFAULT : data.getDataType();
						int size = data == null ? 1 : data.getLength();
						symbol = globalMap.newSymbol(symref, addr, dt, size);
					}
				}
			}
			else if (symbol.getFirstWholeMap() instanceof DynamicEntry) {
				name = symbol.getName();
				symbol.setHighVariable(this);
			}
		}
		//decoder.closeElement(el);
	}

}
