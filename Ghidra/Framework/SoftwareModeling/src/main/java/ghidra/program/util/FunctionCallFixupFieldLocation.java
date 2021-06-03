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
 * The <CODE>FunctionCallFixupFieldLocation</CODE> class provides specific information
 * about the Function call-fixup field within a program location.
 */
public class FunctionCallFixupFieldLocation extends FunctionLocation {

	private String callFixupName;

	/**
	 * Construct a new FunctionCallFixupFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param callFixupName the function call-fixup field text String at this location.
	 * @param charOffset the character position within the field
	 */
	public FunctionCallFixupFieldLocation(Program program, Address locationAddr,
			Address functionAddr, String callFixupName, int charOffset) {

		super(program, locationAddr, functionAddr, 0, 0, charOffset);
		this.callFixupName = callFixupName;
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionCallFixupFieldLocation() {
	}

	/**
	 * Get function call fixup name
	 * @return function call fixup name
	 */
	public String getCallFixupName() {
		return callFixupName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((callFixupName == null) ? 0 : callFixupName.hashCode());
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
		FunctionCallFixupFieldLocation other = (FunctionCallFixupFieldLocation) obj;
		if (callFixupName == null) {
			if (other.callFixupName != null)
				return false;
		}
		else if (!callFixupName.equals(other.callFixupName))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return super.toString() + ", Function Call-Fixup: " + callFixupName;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_FUNCTION_CALLFIXUP_STRING", callFixupName);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		callFixupName = obj.getString("_FUNCTION_CALLFIXUP_STRING", null);
	}

}
