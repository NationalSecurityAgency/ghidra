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

public class DisplayableLocalVariableAddress implements DisplayableAddress {

	protected final Function function;
	protected Address localVariableAddress;

	public DisplayableLocalVariableAddress(Function function, Address localVariableAddress) {
		this.function = function;
		this.localVariableAddress = localVariableAddress;
	}

	@Override
	public Program getProgram() {
		return function.getProgram();
	}

	@Override
	public Address getAddress() {
		return localVariableAddress;
	}

	@Override
	public String getDisplayString() {
		Variable localVariable = getLocalVariable(function, localVariableAddress);
		return getDisplayValue(localVariable);
	}

	public String getDisplayValue(Variable localVariable) {
		if (localVariable == null) {
			return NO_ADDRESS;
		}
		return getString(localVariable) + localVariable.getVariableStorage().toString();
	}

	private Variable getLocalVariable(Function functionToUse, Address localAddressToGet) {
		if ((functionToUse == null) || (localAddressToGet == null)) {
			return null;
		}
		Variable[] localVariables = functionToUse.getLocalVariables();
		for (Variable local : localVariables) {
			if (local.getMinAddress().equals(localAddressToGet)) {
				return local;
			}
		}
		return null;
	}

	private String getString(Variable localVariable) {
		return (localVariable != null) ? ("Local" + " @ ") : "";
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
		if (localVariableAddress == null) {
			return (otherAddress == null) ? 0 : -1;
		}
		if (otherAddress == null) {
			return 1;
		}
		return localVariableAddress.compareTo(otherAddress);
	}

}
