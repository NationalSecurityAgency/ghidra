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
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;

/**
 * A {@link FunctionSignatureFieldLocation} that indicates the user clicked on a function
 * parameter name.
 */
public class FunctionParameterNameFieldLocation extends FunctionParameterFieldLocation {

	private String parameterName;

	/**
	 * Construct a new FunctionParameterNameFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param charOffset the position within the function signature string for this location.
	 * @param signature the function signature string at this location.
	 * @param parameter the function parameter at this location.
	 */
	public FunctionParameterNameFieldLocation(Program program, Address locationAddr,
			Address functionAddr, int charOffset, String signature, Parameter parameter) {
		super(program, locationAddr, functionAddr, charOffset, signature, parameter);
		this.parameterName = parameter.getName();
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionParameterNameFieldLocation() {
	}

	public String getParameterName() {
		return parameterName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((parameterName == null) ? 0 : parameterName.hashCode());
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
		FunctionParameterNameFieldLocation other = (FunctionParameterNameFieldLocation) obj;
		if (parameterName == null) {
			if (other.parameterName != null)
				return false;
		}
		else if (!parameterName.equals(other.parameterName))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_FUNCTION_PARAMETER_NAME", parameterName);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		parameterName = obj.getString("_FUNCTION_PARAMETER_NAME", null);
	}
}
