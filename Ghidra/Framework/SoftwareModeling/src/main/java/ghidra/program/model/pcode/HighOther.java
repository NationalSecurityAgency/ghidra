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

/**
 * 
 *
 * Other forms of variable, these are typically compiler infrastructure
 * like the stackpointer or saved registers
 */
public class HighOther extends HighVariable {

	private DynamicSymbol symbol;
	private Address pcaddr;		// Address of PcodeOp which defines the representative

	/**
	 * Construct a unique high NOT associated with a symbol
	 * @param type data type of variable
	 * @param vn is the representative Varnode
	 * @param inst is the list of Varnodes making up the variable
	 * @param pc code unit address where unique is first assigned (first-use)
	 * @param func the associated high function
	 */
	public HighOther(DataType type, Varnode vn, Varnode[] inst, Address pc, HighFunction func) {
		super(null, type, vn, inst, func);
		pcaddr = pc;
	}

	/**
	 * @return associated dynamic symbol or null
	 */
	@Override
	public DynamicSymbol getSymbol() {
		return symbol;
	}

	/**
	 * @return instruction address the variable comes into scope within the function
	 */
	public Address getPCAddress() {
		return pcaddr;
	}

}
