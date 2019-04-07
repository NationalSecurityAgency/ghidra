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
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;

/**
 * A simple version of {@link OperandFieldLocation} that allows us to store equate information.
 */
public class EquateOperandFieldLocation extends OperandFieldLocation {

	private Equate equate;

	/**
	 * 
	 * @param program The program
	 * @param addr the address of the location
	 * @param refAddr the reference address.
	 * @param rep the representation of the equate location
	 * @param equate the equate object.
	 * @param opIndex the operand index
	 * @param subOpIndex the operand subOpIndex
	 * @param charOffset the character offset in to subOpPiece.
	 */
	public EquateOperandFieldLocation(Program program, Address addr, Address refAddr, String rep,
			Equate equate, int opIndex, int subOpIndex, int charOffset) {
		super(program, addr, (VariableOffset) null, refAddr, rep, opIndex, subOpIndex, charOffset);

		if (equate == null) {
			throw new NullPointerException("Equate parameter cannot be null");
		}

		this.equate = equate;
	}

	/**
	 * Default constructor needed for restoring
	 * an operand field location from XML.
	 */
	public EquateOperandFieldLocation() {
	}

	/**
	 * Returns the equate at this operand field location.
	 * @return equate
	 */
	public Equate getEquate() {
		return equate;
	}

	public long getEquateValue() {
		if (equate == null) {
			// can only happen during a restore if the equate is removed from its address
			return Integer.MIN_VALUE; // what to return?
		}
		return equate.getValue();
	}

	public EquateReference[] getReferences() {
		if (equate == null) {
			// can only happen during a restore if the equate is removed from its address
			return new EquateReference[0];
		}
		return equate.getReferences();
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Equate value = " + getEquateValue();
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (super.equals(obj)) {
			EquateOperandFieldLocation loc = (EquateOperandFieldLocation) obj;
			return SystemUtilities.isEqual(equate, loc.equate);
		}
		return false;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {

		super.restoreState(p, obj);
		long value = obj.getLong("_EQUATE_VALUE", 0);

		EquateTable equateTable = p.getEquateTable();
		equate = equateTable.getEquate(addr, getOperandIndex(), value);
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putLong("_EQUATE_VALUE", getEquateValue());
	}
}
