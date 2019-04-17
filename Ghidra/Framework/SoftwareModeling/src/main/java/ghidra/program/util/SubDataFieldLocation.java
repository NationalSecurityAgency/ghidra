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
 * The <CODE>SubDataFieldLocation</CODE> class contains specific location information
 * within the Sub-data field of a CodeUnitLocation object.
 */
public class SubDataFieldLocation extends CodeUnitLocation {
	private String rep;
	private String fieldName;

	/**
	 * Construct a new SubDataFieldLocation object.
	 * 
	 * @param program the program of the location 
	 * @param addr address of the location
	 * @param path path associated with the address (an address could
	 * appear at more than one group path); may be null
	 * @param componentPath array of indexes for each nested data component;
	 * the index is the data component's index within its parent; may be null 
	 * @param refAddr the "referred to" address if the location is
	 * over a reference; may be null
	 * @param rep the String representation of the operand.
	 * @param charOffset the character position within the operand string.
	 * @param fieldName the name of the sub-data field
	 */
	public SubDataFieldLocation(Program program, Address addr, GroupPath path, int[] componentPath,
			Address refAddr, String rep, int charOffset, String fieldName) {

		super(program, addr, componentPath, refAddr, 0, 0, charOffset);

		this.rep = rep;

		this.fieldName = fieldName;
	}

	/**
	 * Should only be used by XML restoration.
	 */
	public SubDataFieldLocation() {
		super();
	}

	/**
	 * Returns a string representation of the dataValue at this location.
	 */
	public String getDataRepresentation() {
		return rep;
	}

	/**
	 * Returns the name of the sub-data field.
	 */
	public String getFieldName() {
		return fieldName;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", OpRep = " + rep + ", Field Name = " + fieldName;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((fieldName == null) ? 0 : fieldName.hashCode());
		result = prime * result + ((rep == null) ? 0 : rep.hashCode());
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
		SubDataFieldLocation other = (SubDataFieldLocation) obj;
		if (fieldName == null) {
			if (other.fieldName != null)
				return false;
		}
		else if (!fieldName.equals(other.fieldName))
			return false;
		if (rep == null) {
			if (other.rep != null)
				return false;
		}
		else if (!rep.equals(other.rep))
			return false;
		return true;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		rep = obj.getString("_REP", "");
		fieldName = obj.getString("_FIELDNAME", "");
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_REP", rep);
		obj.putString("_FIELDNAME", fieldName);
	}

}
