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
import ghidra.program.model.listing.Program;

/**
 * The <CODE>FunctionNameFieldLocation</CODE> class provides specific information
 * about the Function Name field within a program location.
 */
public class FunctionNameFieldLocation extends FunctionSignatureFieldLocation {

	private String functionName;

	/**
	 * Construct a new FunctionNameFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param charOffset the position within the function signature string for this location.
	 * @param signature the function signature string for this location.
	 * @param functionName the function name String at this location.
	 */
	public FunctionNameFieldLocation(Program program, Address locationAddr, Address functionAddr,
			int charOffset, String signature, String functionName) {
		super(program, locationAddr, functionAddr, charOffset, signature);
		this.functionName = functionName;
	}

	/**
	 * Construct a new FunctionNameFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param functionAddr the function address
	 * @param col the position within the function signature string for this location.
	 * @param signature the function signature string for this location.
	 * @param functionName the function name String at this location.
	 */
	public FunctionNameFieldLocation(Program program, Address functionAddr, int col,
			String signature, String functionName) {
		super(program, functionAddr, col, signature);
		this.functionName = functionName;
	}

	public FunctionNameFieldLocation(Program program, Address addr, String functionName) {
		super(program, addr);
		this.functionName = functionName;
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionNameFieldLocation() {
	}

	public String getFunctionName() {
		return functionName;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Function Name: " + functionName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((functionName == null) ? 0 : functionName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		FunctionNameFieldLocation other = (FunctionNameFieldLocation) obj;
		if (functionName == null) {
			if (other.functionName != null)
				return false;
		}
		else if (!functionName.equals(other.functionName))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_FUNCTION_NAME", functionName);
	}

	@Override
	public void restoreState(Program restoreProgram, SaveState obj) {
		super.restoreState(restoreProgram, obj);
		functionName = obj.getString("_FUNCTION_NAME", null);
	}
}
