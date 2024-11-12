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
package ghidra.app.util.pdb.classtype;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;

public abstract class VirtualFunctionTable implements VFTable {

	protected ClassID owner;
	protected List<ClassID> parentage;

	/**
	 * Virtual Function Table for a base (parent) class within an owner class.  The owner and parent
	 * class can be null if not known, but methods are offered to fill them in if/when this
	 * information becomes available
	 * @param owner class that owns this VBT (can own more than one). Can be null
	 * @param parentage parentage for which this VBT is used.  Can be null
	 */
	VirtualFunctionTable(ClassID owner, List<ClassID> parentage) {
		this.owner = owner;
		this.parentage = new ArrayList<>(parentage);
	}

	/**
	 * Returns the address value at the index in the table
	 * @param index the index
	 * @return the address
	 * @throws PdbException upon error retrieving the value
	 */
	public abstract Address getAddress(int index) throws PdbException;

	/**
	 * Returns the symbol path of the function at the index in the table
	 * @param index the index
	 * @return the symbol path
	 * @throws PdbException upon error retrieving the value
	 */
	public abstract SymbolPath getPath(int index) throws PdbException;

	/**
	 * Returns the owning class
	 * @return the owner
	 */
	public ClassID getOwner() {
		return owner;
	}

	/**
	 * Returns the parentage of the table
	 * @return the parentage
	 */
	public List<ClassID> getParentage() {
		return parentage;
	}

	/**
	 * Sets the owner of the table
	 * @param ownerArg the class to set as owner
	 */
	public void setOwner(ClassID ownerArg) {
		owner = ownerArg;
	}

	/**
	 * Sets the parentage of the parentage for the table
	 * @param parentage the parentage
	 */
	public void setParentage(List<ClassID> parentage) {
		this.parentage = parentage;
	}

	void emit(StringBuilder builder) {
		builder.append("VBT for the following classes within: " + owner);
		builder.append("\n");
		for (ClassID id : parentage) {
			builder.append("   " + id);
			builder.append("\n");
		}
	}
}
