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
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 *
 * A constant that has been given a datatype (like a constant that is really a pointer)
 */
public class HighConstant extends HighVariable {

	private DynamicSymbol symbol;
	private Address pcaddr;		// null or Address of PcodeOp which defines the representative

	/**
	 * Construct a constant NOT associated with a symbol
	 * @param name name of variable
	 * @param type data type of variable
	 * @param vn constant varnode
	 * @param pc code unit address where constant is used
	 * @param func the associated high function
	 * @throws InvalidInputException 
	 */
	public HighConstant(String name, DataType type, Varnode vn, Address pc,
			HighFunction func) throws InvalidInputException {
		super(name, type, vn, null, func);
		pcaddr = pc;
	}

	/**
	 * Construct constant associated with a dynamic symbol
	 * @param name name of variable
	 * @param type data type of variable
	 * @param vn constant varnode
	 * @param pc code unit address where constant is used
	 * @param sym associated dynamic symbol
	 * @throws InvalidInputException 
	 */
	public HighConstant(String name, DataType type, Varnode vn, Address pc,
			DynamicSymbol sym) throws InvalidInputException {
		this(name, type, vn, pc, sym.getHighFunction());
		symbol = sym;
	}

	/**
	 * @return associated dynamic symbol or null
	 */
	public DynamicSymbol getSymbol() {
		return symbol;
	}

	/**
	 * @return instruction address the variable comes into scope within the function
	 */
	public Address getPCAddress() {
		return pcaddr;
	}

	/**
	 * Returns constant as a scalar object
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

}
