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
package ghidra.program.model.reloc;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

import java.util.Iterator;

/**
 * An interface for storing the relocations defined in a program.
 */
public interface RelocationTable {
	/** Name of the relocatable property in the program information property list. */
	public static final String RELOCATABLE_PROP_NAME = "Relocatable";

	/**
	 * Creates and adds a new relocation with the specified
	 * address, type, and value. 
	 * 
	 * @param addr the address where the relocation is required
	 * @param type the type of relocation to perform
	 * @param values the values needed when performing the relocation
	 * @param bytes original instruction bytes affected by relocation
	 * @param symbolName the name of the symbol being relocated; may be null 
	 * @return the newly added relocation object
	 */
	public Relocation add(Address addr, int type, long[] values, byte[] bytes, String symbolName);

	/**
	 * Removes the relocation object.
	 * @param reloc the relocation object to remove
	 */
	public void remove(Relocation reloc);

	/**
	 * Returns the relocation with the specified address.
	 * @param addr the address where the relocation is defined
	 * @return the relocation with the specified address
	 */
	public Relocation getRelocation(Address addr);

	/**
	 * Returns an iterator over all relocation points (in ascending address order) located 
	 * within the program.
	 * @return relocation iterator
	 */
	public Iterator<Relocation> getRelocations();

	/**
	 * Returns an iterator over all the relocation points (in ascending address order) located 
	 * within the specified address set.
	 * @param set address set
	 * @return relocation iterator
	 */
	public Iterator<Relocation> getRelocations(AddressSetView set);

	/**
	 * Returns the next relocation point which follows the specified address.
	 * @param addr starting point
	 * @return next relocation after addr
	 */
	public Relocation getRelocationAfter(Address addr);

	/**
	 * Returns the number of relocation in this table.
	 * @return the number of relocation in this table
	 */
	public int getSize();

	/**
	 * Returns true if this relocation table contains relocations for a relocatable binary.
	 * Some binaries may contain relocations, but not actually be relocatable. For example, ELF executables.
	 * @return true if this relocation table contains relocations for a relocatable binary
	 */
	public boolean isRelocatable();
}
