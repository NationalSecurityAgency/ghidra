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
import ghidra.program.model.listing.VariableOffset;

/**
 * The <CODE>OperandFieldLocation</CODE> class contains specific location information
 * within the OPERAND field of a CodeUnitLocation object.
 */
public class OperandFieldLocation extends CodeUnitLocation {

	private String rep;
	private int subOpIndex = -1;
	private VariableOffset variableOffset;

	/**
	 * Construct a new OperandFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param componentPath array of indexes for each nested data component; the
	 * index is the data component's index within its parent; may be null
	 * @param rep the String representation of the operand.
	 * @param opIndex the index of the operand at this location.
	 * @param characterOffset the character position from the beginning of the operand.
	 */
	public OperandFieldLocation(Program program, Address addr, int[] componentPath,
			Address refAddr, String rep, int opIndex, int characterOffset) {

		super(program, addr, componentPath, refAddr, 0, opIndex, characterOffset);

		this.rep = rep;
		this.subOpIndex = -1;
	}

	/**
	 * Construct a new OperandFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param componentPath array of indexes for each nested data component; the
	 * index is the data component's index within its parent; may be null
	 * @param refAddr the "referred to" address if the location is
	 * over a reference; may be null
	 * @param rep the String representation of the operand.
	 * @param opIndex the index indicating the operand the location is on.
	 * @param subOpIndex the index of the Object within the operand, this can
	 *                   be used to call an instructions getOpObjects() method
	 * @param characterOffset the character position from the beginning of the operand field
	 */
	public OperandFieldLocation(Program program, Address addr, int[] componentPath,
			Address refAddr, String rep, int opIndex, int subOpIndex, int characterOffset) {

		super(program, addr, componentPath, refAddr, 0, opIndex, characterOffset);

		this.rep = rep;
		this.subOpIndex = subOpIndex;
	}

	/**
	 * Construct a new OperandFieldLocation object for an instruction operand.
	 * 
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param variableOffset associated variable offset or null
	 * @param refAddr the "referred to" address if the location is
	 * over a reference; may be null
	 * @param rep the String representation of the operand.
	 * @param opIndex the index indicating the operand the location is on.
	 * @param subOpIndex the index of the Object within the operand, this can
	 *                   be used to call an instructions getOpObjects() method
	 * @param characterOffset the character position from the beginning of the operand field
	 */
	public OperandFieldLocation(Program program, Address addr, VariableOffset variableOffset,
			Address refAddr, String rep, int opIndex, int subOpIndex, int characterOffset) {

		super(program, addr, null, refAddr, 0, opIndex, characterOffset);

		this.rep = rep;
		this.subOpIndex = subOpIndex;
		this.variableOffset = variableOffset;
	}

	/**
	* Default constructor needed for restoring
	* an operand field location from XML.
	*/
	public OperandFieldLocation() {
	}

	/**
	 * Returns VariableOffset object if applicable or null
	 */
	public VariableOffset getVariableOffset() {
		return variableOffset;
	}

	/**
	 * Returns a string representation of the opernand at this location.
	 */
	public String getOperandRepresentation() {
		return rep;
	}

	/**
	 * Returns the index of the operand at this location.
	 */
	public int getOperandIndex() {
		return getColumn();
	}

	/**
	 * Returns the sub operand index at this location.
	 * This index can be used on the instruction.getOpObjects()
	 * to find the actual object (Address, Register, Scalar) the
	 * cursor is over.
	 * @return 0-n if over a valid OpObject, -1 otherwise
	 */
	public int getSubOperandIndex() {
		return subOpIndex;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", OpRep = " + rep + ", subOpIndex = " + subOpIndex +
			", VariableOffset = " + variableOffset;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((rep == null) ? 0 : rep.hashCode());
		result = prime * result + subOpIndex;
		result = prime * result + ((variableOffset == null) ? 0 : variableOffset.hashCode());
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
		OperandFieldLocation other = (OperandFieldLocation) obj;
		if (rep == null) {
			if (other.rep != null)
				return false;
		}
		else if (!rep.equals(other.rep))
			return false;
		if (subOpIndex != other.subOpIndex)
			return false;
		if (variableOffset == null) {
			if (other.variableOffset != null)
				return false;
		}
		else if (!variableOffset.equals(other.variableOffset))
			return false;
		return true;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		rep = obj.getString("_REP", "");
		subOpIndex = obj.getInt("_SUBOPINDEX", subOpIndex);
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putString("_REP", rep);
		obj.putInt("_SUBOPINDEX", subOpIndex);
	}

}
