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
 * Provides information about the location of an object that 
 * represents the tag names assigned to a function.
 */
public class FunctionTagFieldLocation extends FunctionLocation {

	private String tags;

	/**
	 * Construct a new FunctionTagFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param tags the function tag field text.
	 * @param charOffset the character position within the field
	 */
	public FunctionTagFieldLocation(Program program, Address locationAddr,
			Address functionAddr, String tags, int charOffset) {
		super(program, locationAddr, functionAddr, 0, 0, charOffset);
		this.tags = tags;
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionTagFieldLocation() {
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((tags == null) ? 0 : tags.hashCode());
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
		FunctionTagFieldLocation other = (FunctionTagFieldLocation) obj;
		if (tags == null) {
			if (other.tags != null)
				return false;
		}
		else if (!tags.equals(other.tags))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return super.toString() + ", Function Tags: " + tags;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_FUNCTION_TAGS", tags);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		tags = obj.getString("_FUNCTION_TAGS", null);
	}
}
