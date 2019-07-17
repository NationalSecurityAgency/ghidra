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
package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class FunctionParameterFieldLocation extends FunctionSignatureFieldLocation {

	private Parameter parameter; // NOTE: this can be null after restoreState() is called!
	private int ordinal;

	/**
	 * Construct a new FunctionParameterFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param charOffset the position within the function signature string for this location.
	 * @param signature the function signature string at this location.
	 * @param parameter the function parameter at this location.
	 */
	public FunctionParameterFieldLocation(Program program, Address locationAddr,
			Address functionAddr, int charOffset, String signature, Parameter parameter) {
		super(program, locationAddr, functionAddr, charOffset, signature);
		this.parameter = parameter;

		// note: the parameter can be null if it is deleted in the background while this
		//       location is being created
		this.ordinal = parameter == null ? -1 : parameter.getOrdinal();
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionParameterFieldLocation() {
	}

	/**
	 * Returns the parameter associated with this location.  This value can be null if the 
	 * parameters are deleted from the function associated with the address of the parameter.
	 * @return the parameter
	 */
	public Parameter getParameter() {
		return parameter;
	}

	public int getOrdinal() {
		return ordinal;
	}

	@Override
	public boolean equals(Object obj) {
		if (super.equals(obj)) {
			FunctionParameterFieldLocation other = (FunctionParameterFieldLocation) obj;
			return ordinal == other.ordinal;
		}
		return false;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Function Parameter: " + parameter;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putInt("_FUNCTION_PARAMETER_ORDINAL", ordinal);
	}

	@Override
	public void restoreState(Program restoreProgram, SaveState obj) {
		super.restoreState(restoreProgram, obj);
		ordinal = obj.getInt("_FUNCTION_PARAMETER_ORDINAL", -1);
		Function function = restoreProgram.getFunctionManager().getFunctionAt(functionAddr);
		if (function != null) {
			parameter = function.getParameter(ordinal);
		}
	}
}
