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
package ghidra.feature.vt.gui.provider.markuptable;

import ghidra.feature.vt.gui.editors.DisplayableAddress;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class DisplayableParameterAddress implements DisplayableAddress {

	protected final Function function;
	protected Address parameterAddress;

	public DisplayableParameterAddress(Function function, Address parameterAddress) {
		this.function = function;
		this.parameterAddress = parameterAddress;
	}

	@Override
	public Program getProgram() {
		return function.getProgram();
	}

	@Override
	public Address getAddress() {
		return parameterAddress;
	}

	@Override
	public String getDisplayString() {
		Parameter parameter = getParameter(function, parameterAddress);
		return getDisplayValue(parameter);
	}

	public String getDisplayValue(Parameter parameter) {
		if (parameter == null) {
			return NO_ADDRESS;
		}
		return getOrdinalString(parameter) + parameter.getVariableStorage().toString();
	}

	private Parameter getParameter(Function functionToUse, Address parameterAddressToGet) {
		if ((functionToUse == null) || (parameterAddressToGet == null)) {
			return null;
		}
		Parameter[] parameters = functionToUse.getParameters();
		for (Parameter parameter : parameters) {
			if (parameter.getMinAddress().equals(parameterAddressToGet)) {
				return parameter;
			}
		}
		return null;
	}

	private String getOrdinalString(Parameter parameter) {
		return (parameter != null) ? ("Parameter " + (parameter.getOrdinal() + 1) + " @ ") : "";
	}

	@Override
	public String toString() {
		return getDisplayString();
	}

	@Override
	public int compareTo(DisplayableAddress otherDisplayableAddress) {
		if (otherDisplayableAddress == null) {
			return 1;
		}
		Address otherAddress = otherDisplayableAddress.getAddress();
		if (parameterAddress == null) {
			return (otherAddress == null) ? 0 : -1;
		}
		if (otherAddress == null) {
			return 1;
		}
		return parameterAddress.compareTo(otherAddress);
	}

}
