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
package ghidra.program.model.symbol;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * An Equate associates a string with a scalar value in the program, 
 * and contains a list of addresses and operand positions that refer 
 * to this equate.
 */
public interface Equate {

	/**
	 * Get the actual name of this equate.  Note that this name may be different than the
	 * "display name," which is what the user will see.
	 * 
	 * @return The actual name of this equate.
	 */
	public String getName();

	/**
	 * Gets the "display name" of this equate.  Note that the display name may be different
	 * than the equate's actual name if the equate is based off a data type id.
	 * 
	 * @return The "display name" of this equate.
	 */
	public String getDisplayName();

	/**
	 * Get the value of this equate.
	 */
	public long getValue();

	/**
	 * Gets a more accurate representation of the equate value. Used for rendering as close to the
	 * listing as possible. 
	 * @return A more accurate representation of the equate value.
	 */
	public String getDisplayValue();

	/**
	 * Get the number of references to this equate.
	 */
	public int getReferenceCount();

	/**
	 * Add a reference (at the given operand position) to this equate.  If a reference already
	 * exists for the instruction at this address, then the old reference will be removed
	 * before the new reference is added.
	 * 
	 * @param refAddr the address where the equate is used.
	 * @param opndPosition the operand index where the equate is used.
	 */
	public void addReference(Address refAddr, int opndPosition);

	/**
	 * Add a reference (at the given dynamic hash position) to this equate. If a reference already
	 * exists for the instruction at this address, then the old reference will be removed
	 * before the new reference is added.
	 * 
	 * @param dynamicHash constant varnode dynamic hash value
	 * @param refAddr the address where the equate is used.
	 */
	public void addReference(long dynamicHash, Address refAddr);

	/**
	 * Changes the name associated with the equate.
	 * @param newName the new name for this equate.
	 * @exception DuplicateNameException thrown if newName is already
	 *   used by another equate.
	 * @throws InvalidInputException if newName contains blank characters,
	 * is zero length, or is null
	 */
	void renameEquate(String newName) throws DuplicateNameException, InvalidInputException;

	/**
	 * Get the references for this equate.
	 * @return a array of EquateReferences. 
	 */
	public EquateReference[] getReferences();

	/**
	 * Get references for this equate attached to a specific address
	 * @param refAddr is the address
	 * @return the list of EquateReferences
	 */
	public List<EquateReference> getReferences(Address refAddr);

	/**
	 * Remove the reference at the given operand position.
	 * @param refAddr the address that was using this equate
	 * @param opndPosition the operand index of the operand that was using this eqate.
	 */
	public void removeReference(Address refAddr, int opndPosition);

	/**
	 * Remove the reference at the given address
	 * @param dynamicHash the hash of the reference
	 * @param refAddr the reference's address
	 */
	public void removeReference(long dynamicHash, Address refAddr);

	/**
	 * Checks if equate is based off an enum's universal id and checks if the enum still exists.
	 * The equate is still valid if the equate is not based off an enum.
	 * @return true if the equate is based off an enum that still exists.
	 */
	public boolean isValidUUID();

	/**
	 * Checks if equate is based off an enum's universal id.
	 * @return
	 */
	public boolean isEnumBased();

	/**
	 * Gets the universal id from this equate if the equate was based off of an enum.
	 * @return The universal id for this equate.
	 */
	public UniversalID getEnumUUID();

	/**
	 * Get the name of this equate.
	 * @see #getName()
	 */
	@Override
	public String toString();
}
