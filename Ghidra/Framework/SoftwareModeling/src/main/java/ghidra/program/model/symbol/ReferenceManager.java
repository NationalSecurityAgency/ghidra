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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Interface for managing references.
 */
public interface ReferenceManager {
	/**
	 * Operand index which corresponds to the instruction/data mnemonic.
	 */
	public static final int MNEMONIC = Reference.MNEMONIC;

	/**
	 * Add a memory, stack, register or external reference
	 * @param reference reference to be added
	 * @return new reference
	 */
	public Reference addReference(Reference reference);

	/**
	 * Add a reference to a stack location. If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr "from" address within a function
	 * @param opIndex operand index
	 * @param stackOffset stack offset of the reference
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 * @return new stack reference
	 */
	public Reference addStackReference(Address fromAddr, int opIndex, int stackOffset, RefType type,
			SourceType source);

	/**
	 * Add a reference to a register. If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * @param fromAddr "from" address
	 * @param opIndex operand index
	 * @param register register to add the reference to
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 * @return new register reference
	 */
	public Reference addRegisterReference(Address fromAddr, int opIndex, Register register,
			RefType type, SourceType source);

	/**
	 * Adds a memory reference.  The first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.  Certain reference {@link RefType types}
	 * may not be specified (e.g., {@link RefType#FALL_THROUGH}).
	 * @param fromAddr address of the code unit where the reference occurs
	 * @param toAddr address of the location being referenced.  
	 * Memory, stack, and register addresses are all permitted.
	 * @param type reference type - how the location is being referenced.
	 * @param source the source of this reference
	 * @param opIndex the operand index 
	 * display of the operand making this reference
	 * @return new memory reference
	 * @throws IllegalArgumentException if unsupported {@link RefType type} is specified
	 */
	public Reference addMemoryReference(Address fromAddr, Address toAddr, RefType type,
			SourceType source, int opIndex);

	/**
	 * Add an offset memory reference.  The first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.  If toAddr corresponds to
	 * the EXTERNAL memory block (see {@link MemoryBlock#EXTERNAL_BLOCK_NAME}) the
	 * resulting offset reference will report to/base address as the same
	 * regardless of specified offset.
	 * @param fromAddr address for the "from"
	 * @param toAddr address of the location being referenced. 
	 * @param toAddrIsBase if true toAddr is treated as base address, else treated as (base+offet).
	 * It is generally preferred to specify as a base address to ensure proper handling of
	 * EXTERNAL block case.
	 * @param offset value added to a base address to get the toAddr
	 * @param type reference type - how the location is being referenced
	 * @param source the source of this reference
	 * @param opIndex the operand index
	 * @return new offset reference
	 */
	public Reference addOffsetMemReference(Address fromAddr, Address toAddr, boolean toAddrIsBase,
			long offset, RefType type, SourceType source, int opIndex);

	/**
	 * Add a shifted memory reference; the "to" address is computed as the value
	 * at the operand at opIndex shifted by some number of bits, specified in the 
	 * shiftValue parameter.  The first memory reference placed on
	 * an operand will be made primary by default.  All non-memory references 
	 * will be removed from the specified operand.
	 * 
	 * @param fromAddr source/from memory address
	 * @param toAddr destination/to memory address computed as some 
	 * {@link ShiftedReference#getValue() base offset value} shifted left
	 * by the number of bits specified by shiftValue.  The least-significant bits of toAddr
	 * offset should be 0's based upon the specified shiftValue since this value is shifted
	 * right to calculate the base offset value.
	 * @param shiftValue number of bits to shift
	 * @param type reference type - how the location is being referenced
	 * @param source the source of this reference
	 * @param opIndex the operand index
	 * @return new shifted reference
	 */
	public Reference addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
			RefType type, SourceType source, int opIndex);

	/**
	 * Adds an external reference to an external symbol.  If a reference already
	 * exists at {@code fromAddr} and {@code opIndex} the existing reference is replaced
	 * with a new reference.  If the external symbol cannot be found, a new {@link Library} 
	 * and/or {@link ExternalLocation} symbol will be created which corresponds to the specified
	 * library/file named {@code libraryName}
	 * and the location within that file identified by {@code extLabel} and/or its memory address
	 * {@code extAddr}.  Either or both {@code extLabel} or {@code extAddr} must be specified.
	 * 
	 * @param fromAddr from memory address (source of the reference)
	 * @param libraryName name of external program
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr memory address within the external program, may be null
	 * @param source the source of this reference
	 * @param opIndex operand index
	 * @param type reference type - how the location is being referenced
	 * @return new external space reference
	 * @throws InvalidInputException if {@code libraryName} is invalid or null, or an invalid 
	 * {@code extlabel} is specified.  Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public Reference addExternalReference(Address fromAddr, String libraryName, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Adds an external reference.  If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * 
	 * @param fromAddr from memory address (source of the reference)
	 * @param extNamespace external namespace containing the named external label.
	 * @param extLabel label within the external program, may be null if extAddr is not null
	 * @param extAddr address within the external program, may be null
	 * @param source the source of this reference
	 * @param opIndex operand index
	 * @param type reference type - how the location is being referenced
	 * @return new external space reference
	 * @throws InvalidInputException if an invalid {@code extlabel} is specified.  
	 * Names with spaces or the empty string are not permitted.
	 * Neither {@code extLabel} nor {@code extAddr} was specified properly.
	 * @throws DuplicateNameException if another non-Library namespace has the same name
	 * @throws IllegalArgumentException if an invalid {@code extAddr} was specified.
	 */
	public Reference addExternalReference(Address fromAddr, Namespace extNamespace, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException;

	/**
	 * Adds an external reference.  If a reference already
	 * exists for the fromAddr and opIndex, the existing reference is replaced
	 * with the new reference.
	 * 
	 * @param fromAddr from memory address (source of the reference)
	 * @param opIndex operand index
	 * @param location external location
	 * @param source the source of this reference
	 * @param type reference type - how the location is being referenced
	 * @return external reference
	 * @throws InvalidInputException if the input is invalid
	 */
	public Reference addExternalReference(Address fromAddr, int opIndex, ExternalLocation location,
			SourceType source, RefType type) throws InvalidInputException;

	/**
	 * Removes all references where "From address" is in the given range.
	 * @param beginAddr the first address in the range.
	 * @param endAddr the last address in the range.
	 */
	public void removeAllReferencesFrom(Address beginAddr, Address endAddr);

	/**
	 * Remove all stack, external, and memory references for the given
	 * from address.
	 * @param fromAddr the address of the code unit from which to remove all references.
	 */
	public void removeAllReferencesFrom(Address fromAddr);

	/**
	 * Remove all stack, external, and memory references for the given
	 * to address.
	 * @param toAddr the address for which all references to should be removed.
	 */
	public void removeAllReferencesTo(Address toAddr);

	/**
	 * Returns all references to the given variable.  Only data references to storage 
	 * are considered.
	 * @param var variable to retrieve references to
	 * @return array of variable references, or zero length array if no
	 * references exist
	 */
	public Reference[] getReferencesTo(Variable var);

	/**
	 * Returns the referenced function variable. 
	 * @param reference variable reference
	 * @return function variable or null if variable not found
	 */
	public Variable getReferencedVariable(Reference reference);

	/**
	 * Set the given reference's primary attribute
	 * @param ref the reference to make primary.
	 * @param isPrimary true to make the reference primary, false to make it non-primary
	 */
	public void setPrimary(Reference ref, boolean isPrimary);

	/**
	 * Return whether the given address has flow references from it.
	 * @param addr the address to test for flow references.
	 * @return true if the given address has flow references from it, else false
	 */
	public boolean hasFlowReferencesFrom(Address addr);

	/**
	 * Get all flow references from the given address.
	 * @param addr the address of the code unit to get all flows from.
	 * @return get all flow references from the given address.
	 * 
	 */
	public Reference[] getFlowReferencesFrom(Address addr);

	/**
	 * Returns an iterator over all external space references
	 * @return reference iterator over all external space references
	 */
	public ReferenceIterator getExternalReferences();

	/**
	 * Get an iterator over all references that have the given address as
	 * their "To" address.
	 * @param addr the address that all references in the iterator refer to.
	 * @return reference iterator over all references to the specified address.
	 */
	public ReferenceIterator getReferencesTo(Address addr);

	/**
	 * Get an iterator over references starting with the specified 
	 * fromAddr.  A forward iterator is returned with references sorted on
	 * the from address.
	 * @param startAddr the first from address to consider.
	 * @return a forward memory reference iterator.
	 */
	public ReferenceIterator getReferenceIterator(Address startAddr);

	/**
	 * Get the reference that has the given from and to address, and
	 * operand index.
	 * @param fromAddr the address of the code unit making the reference.
	 * @param toAddr the address being referred to.
	 * @param opIndex the operand index.
	 * @return reference which satisfies the specified criteria or null
	 */
	public Reference getReference(Address fromAddr, Address toAddr, int opIndex);

	/**
	 * Get all references "from" the specified addr.
	 * @param addr address of code-unit making the references.
	 * @return array of all references "from" the specified addr.
	 */
	public Reference[] getReferencesFrom(Address addr);

	/**
	 * Returns all references "from" the given fromAddr and operand (specified by opIndex).
	 * @param fromAddr the from which to get references
	 * @param opIndex the operand from which to get references
	 * @return all references "from" the given fromAddr and operand.
	 */
	public Reference[] getReferencesFrom(Address fromAddr, int opIndex);

	/**
	 * Returns true if there are any memory references at the given
	 * address/opIndex.  Keep in mind this is a rather inefficient 
	 * method as it must examine all references from the specified 
	 * fromAddr.
	 * @param fromAddr the address of the code unit being tested
	 * @param opIndex the index of the operand being tested.
	 * @return true if one or more reference from the specified address
	 * and opindex are defined, else false
	 */
	public boolean hasReferencesFrom(Address fromAddr, int opIndex);

	/**
	 * Returns true if there are any memory references at the given
	 * address. 
	 * @param fromAddr the address of the code unit being tested
	 * @return true if one or more reference from the specified address
	 * are defined, else false
	 */
	public boolean hasReferencesFrom(Address fromAddr);

	/**
	 * Get the primary reference from the given address.
	 * @param addr from address
	 * @param opIndex operand index
	 * @return the primary reference from the specified address
	 * and opindex if it exists, else null
	 */
	public Reference getPrimaryReferenceFrom(Address addr, int opIndex);

	/**
	 * Returns an iterator over addresses that are the "From" address in a
	 * reference
	 * @param startAddr address to position iterator.
	 * @param forward true means to iterate in the forward direction
	 * @return address iterator where references from exist
	 */
	public AddressIterator getReferenceSourceIterator(Address startAddr, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "From" address in a
	 * reference, restricted by the given address set.
	 * @param addrSet the set of address to restrict the iterator or null for all addresses.
	 * @param forward true means to iterate in the forward direction
	 * address iterator where references from exist
	 * @return address iterator where references from exist constrained by addrSet
	 */
	public AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "To" address in a
	 * reference.
	 * @param startAddr start of iterator
	 * @param forward true means to iterate in the forward direction
	 * address iterator where references to exist
	 * @return address iterator where references to exist
	 */
	public AddressIterator getReferenceDestinationIterator(Address startAddr, boolean forward);

	/**
	 * Returns an iterator over all addresses that are the "To" address in a
	 * memory reference, restricted by the given address set.
	 * @param addrSet the set of address to restrict the iterator or null for all addresses.
	 * @param forward true means to iterate in the forward direction
	 * @return address iterator where references to exist constrained by addrSet
	 */
	public AddressIterator getReferenceDestinationIterator(AddressSetView addrSet, boolean forward);

	/**
	 * Returns the number of references to the specified <code>toAddr</code>.
	 * @param toAddr the address being referenced
	 * @return the number of references to the specified <code>toAddr</code>.
	 */
	public int getReferenceCountTo(Address toAddr);

	/**
	 * Returns the number of references from the specified <code>fromAddr</code>.
	 * @param fromAddr the address of the code unit making the reference.
	 * @return the number of references from the specified <code>fromAddr</code>.
	 */
	public int getReferenceCountFrom(Address fromAddr);

	/**
	 * Return the number of references for "to" addresses.
	 * @return the number of references for "to" addresses.
	 */
	public int getReferenceDestinationCount();

	/**
	 * Return the number of references for "from" addresses.
	 * @return the number of references for "from" addresses.
	 */
	public int getReferenceSourceCount();

	/**
	 * Return true if a memory reference exists with the given "to" address.
	 * @param toAddr address being referred to.
	 * @return true if specified toAddr has one or more references to it, else false.
	 */
	public boolean hasReferencesTo(Address toAddr);

	/**
	 * Update the reference type on a memory reference.
	 * @param ref reference to be updated
	 * @param refType new reference type
	 * @return updated reference
	 */
	public Reference updateRefType(Reference ref, RefType refType);

	/**
	 * Associates the given reference with the given symbol.
	 * Applies to memory references only where a specified label symbol must have 
	 * an address which matches the reference to-address.  Stack and register 
	 * reference associations to variable symbols are always inferred.
	 * @param s the symbol to associate with the given reference.
	 * @param ref the reference to associate with the given symbol
	 * @throws IllegalArgumentException If the given reference does not already
	 * exist or its "To" address
	 * is not the same as the symbol's address. 
	 */
	public void setAssociation(Symbol s, Reference ref);

	/**
	 * Removes any symbol associations with the given reference.
	 * @param ref the reference for which any symbol association is to be removed.
	 * @throws IllegalArgumentException if the given references does not exist.
	 */
	public void removeAssociation(Reference ref);

	/**
	 * Deletes the given reference object
	 * @param ref the reference to be deleted.
	 */
	public void delete(Reference ref);

	/**
	 * Returns the reference level for the references to the given address
	 * @param toAddr the address at which to find the highest reference level
	 * @return reference level for specified to address.
	 */
	public byte getReferenceLevel(Address toAddr);

}
