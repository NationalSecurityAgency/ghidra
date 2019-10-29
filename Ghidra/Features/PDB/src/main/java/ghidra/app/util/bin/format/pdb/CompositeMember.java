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
package ghidra.app.util.bin.format.pdb;

import ghidra.program.model.data.BitFieldDataType;

/**
 * <code>CompositeMember</code> provides a composite construction member interface for use
 * by the PDB parser.
 */
abstract class CompositeMember {

	/**
	 * Due to the dynamic restructuring of data type containers, this method should be invoked
	 * on the root container prior to adding or applying the associated data type to the program.  
	 * This method will appropriately rename and categorize associated anonymous structures and 
	 * unions to reflect the final organization and check if internal alignment should be enabled.
	 * @param preferredSize preferred size of composite if known, else <= 0 if unknown
	 */
	abstract void finalizeDataType(int preferredSize);

	/**
	 * Determine if this member is a container
	 * @return true if container, else false
	 */
	abstract boolean isContainer();

	/**
	 * Determine if this member is a union container
	 * @return true if union container, else false
	 */
	abstract boolean isUnionContainer();

	/**
	 * Determine if this member is a structure container
	 * @return true if structure container, else false
	 */
	abstract boolean isStructureContainer();

	/**
	 * Determine if this member is a bit-field member or group.
	 * @return true if bit-field member, else false
	 */
	abstract boolean isBitFieldMember();

	/**
	 * Determine if this member is a bit-field member not yet contained within a group.
	 * If true is returned this instance is ensured to be a {@link DefaultCompositeMember} instance 
	 * whose data type is {@link BitFieldDataType}.
	 * @return true if bit-field member not yet contained within a group
	 */
	abstract boolean isSingleBitFieldMember();

	/**
	 * Get the offset of this member relative to the start of its parent container.
	 * @return relative member offset or -1 for root container
	 */
	abstract int getOffset();

	/**
	 * Set the offset of this member relative to the start of its parent container.
	 * @param offset relative member offset
	 */
	abstract void setOffset(int offset);

	/**
	 * Get the data type length associated with this member.  Container members data-type
	 * length may continue to grow as additional members are added.
	 * @return data type associated with this member.
	 */
	abstract int getLength();

	/**
	 * Get the parent which corresponds to this member
	 * @return parent
	 */
	abstract DefaultCompositeMember getParent();

	/**
	 * Set the composite parent which contains this member
	 * @param parent new parent
	 */
	abstract void setParent(DefaultCompositeMember parent);

	/**
	 * Add specified member to this member.  If this member is not a composite 
	 * it will trigger the creation 
	 * @param member
	 * @return
	 */
	abstract boolean addMember(DefaultCompositeMember member);

	/**
	 * Instructs this member to add itself to the specified structure
	 * @param structure composite structure
	 */
	abstract boolean addToStructure(DefaultCompositeMember structure);
}
