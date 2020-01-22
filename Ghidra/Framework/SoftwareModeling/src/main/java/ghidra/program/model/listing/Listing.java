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
package ghidra.program.model.listing;

import java.util.Iterator;
import java.util.List;

import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * This interface provides all the methods needed to create,delete, retrieve,
 * modify code level constructs (CodeUnits, Macros, Fragments, and Modules).
 */

public interface Listing {
	/**
	 * get the code unit that starts at the given address.
	 *
	 * @param addr the address to look for a codeUnit.
	 * @return the codeUnit that begins at the given address
	 */
	public CodeUnit getCodeUnitAt(Address addr);

	/**
	 * get the code unit that contains the given address.
	 *
	 * @param addr the address to look for a codeUnit.
	 * @return the codeUnit that contains the given address
	 */
	public CodeUnit getCodeUnitContaining(Address addr);

	/**
	 * get the next code unit that starts an an address that is greater than the
	 * given address. The search will include instructions, defined data, and
	 * undefined data.
	 *
	 * @param addr the address from which to search forward.
	 * @return the next CodeUnit found while searching forward from addr or null
	 *         if none found.
	 */
	public CodeUnit getCodeUnitAfter(Address addr);

	/**
	 * get the next code unit that starts at an address that is less than the
	 * given address. The search will include instructions, defined data, and
	 * undefined data.
	 *
	 * @param addr the address from which to search backwards.
	 * @return The first codeUnit found while searching backwards from addr or
	 *         null if none found.
	 */
	public CodeUnit getCodeUnitBefore(Address addr);

	/**
	 * Get an iterator that contains all code units in the program which have
	 * the specified property type defined. Standard property types are defined
	 * in the CodeUnit class. The property types are: EOL_COMMENT, PRE_COMMENT,
	 * POST_COMMENT, USER_REFERENCE, MNEMONIC_REFERENCE, VALUE_REFERENCE.
	 * Property types can also be user defined.
	 *
	 * @param property the name of the property type.
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         start address that have the specified property type defined.
	 */
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward);

	/**
	 * Get an iterator that contains the code units which have the specified
	 * property type defined. Only code units at an address greater than or
	 * equal to the specified start address will be returned by the iterator. If
	 * the start address is null then check the entire program. Standard
	 * property types are defined in the CodeUnit class. The property types are:
	 * EOL_COMMENT, PRE_COMMENT, POST_COMMENT, USER_REFERENCE,
	 * MNEMONIC_REFERENCE, VALUE_REFERENCE. Property types can also be user
	 * defined.
	 *
	 * @param property the name of the property type. (EOL_COMMENT, PRE_COMMENT,
	 *            POST_COMMENT, USER_REFERENCE, MNEMONIC_REFERENCE,
	 *            VALUE_REFERENCE)
	 * @param addr the start address
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         start address that have the specified property type defined.
	 */
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward);

	/**
	 * Get an iterator that contains the code units which have the specified
	 * property type defined. Only code units starting within the address set
	 * will be returned by the iterator. If the address set is null then check
	 * the entire program. Standard property types are defined in the CodeUnit
	 * class.
	 *
	 * @param property the name of the property type.
	 * @param addrSet the address set
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         address set that have the specified property type defined.
	 */
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward);

	/**
	 * Get a forward code unit iterator over code units that have the specified
	 * comment type.
	 * 
	 * @param commentType type defined in CodeUnit
	 * @param addrSet address set
	 * @return a CodeUnitIterator that returns all code units from the indicated
	 *         address set that have the specified comment type defined
	 */
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet);

	/**
	 * Get a forward iterator over addresses that have the specified comment
	 * type.
	 * 
	 * @param commentType type defined in CodeUnit
	 * @param addrSet address set
	 * @param forward true to iterator from lowest address to highest, false
	 *            highest to lowest
	 * @return an AddressIterator that returns all addresses from the indicated
	 *         address set that have the specified comment type defined
	 */
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward);

	/**
	 * Get a forward iterator over addresses that have any type of comment.
	 * 
	 * @param addrSet address set
	 * @param forward true to iterator from lowest address to highest, false
	 *            highest to lowest
	 * @return an AddressIterator that returns all addresses from the indicated
	 *         address set that have any type of comment.
	 */
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward);

	/**
	 * Get the comment for the given type at the specified address.
	 *
	 * @param commentType either EOL_COMMENT, PRE_COMMENT, POST_COMMENT,
	 *            PLATE_COMMENT, or REPEATABLE_COMMENT
	 * @param address the address of the comment.
	 * @return the comment string of the appropriate type or null if no comment
	 *         of that type exists for this codeunit
	 * @throws IllegalArgumentException if type is not one of the types of
	 *             comments supported
	 */
	public String getComment(int commentType, Address address);

	/**
	 * Set the comment for the given comment type at the specified address.
	 *
	 * @param address the address of the comment.
	 * @param commentType either EOL_COMMENT, PRE_COMMENT, POST_COMMENT,
	 *            PLATE_COMMENT, or REPEATABLE_COMMENT
	 * @param comment comment to set at the address
	 * @throws IllegalArgumentException if type is not one of the types of
	 *             comments supported
	 */
	public void setComment(Address address, int commentType, String comment);

	/**
	 * get a CodeUnit iterator that will iterate over the entire address space.
	 * 
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator in forward direction
	 */
	public CodeUnitIterator getCodeUnits(boolean forward);

	/**
	 * Returns an iterator of the code units in this listing (in proper
	 * sequence), starting at the specified address. The specified address
	 * indicates the first code unit that would be returned by an initial call
	 * to the <code>next</code> method. An initial call to the <code>previous</code>
	 * method would return the code unit with an address less than the specified
	 * address.
	 * <p>
	 *
	 * @param addr the start address of the iterator.
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator positioned just before addr.
	 */
	public CodeUnitIterator getCodeUnits(Address addr, boolean forward);

	/**
	 * Get an iterator over the address range(s). Only code units whose start
	 * addresses are contained in the given address set will be returned by the
	 * iterator.
	 *
	 * @param addrSet the AddressRangeSet to iterate over.
	 * @param forward true means get iterator in forward direction
	 * @return a CodeUnitIterator that is restricted to the give
	 *         AddressRangeSet.
	 */
	public CodeUnitIterator getCodeUnits(AddressSetView addrSet, boolean forward);

	/**
	 * get the Instruction that starts at the given address. If no Instruction
	 * has been defined to start at that address, return null.
	 *
	 * @param addr the address to check for the start of an instruction
	 * @return the Instruction object that starts at addr; or null if no
	 *         Instructions starts at addr.
	 */
	public Instruction getInstructionAt(Address addr);

	/**
	 * get the Instruction that contains the given address. If an Instruction is
	 * defined that contains that address, it will be returned. Otherwise, null
	 * will be returned.
	 *
	 * @param addr the address to check for containment in an Instruction.
	 * @return the Instruction object that contains addr; or null if no
	 *         Instructions contain addr.
	 */
	public Instruction getInstructionContaining(Address addr);

	/**
	 * get the closest Instruction that starts at an address that is greater
	 * than the given address.
	 *
	 * @param addr The address at which to begin the forward search.
	 * @return the next Instruction whose starting address is greater than addr.
	 */
	public Instruction getInstructionAfter(Address addr);

	/**
	 * get the closest Instruction that starts at an address that is less than
	 * the given address.
	 *
	 * @param addr The address at which to begin the backward search.
	 * @return the closest Instruction whose starting address is less than addr.
	 */
	public Instruction getInstructionBefore(Address addr);

	/**
	 * get an Instruction iterator that will iterate over the entire address
	 * space.
	 *
	 * @param forward true means get iterator in forward direction
	 * @return an InstructionIterator that iterates over all instructions in the
	 *         program.
	 */
	public InstructionIterator getInstructions(boolean forward);

	/**
	 * Returns an iterator of the instructions in this listing (in proper
	 * sequence), starting at the specified address. The specified address
	 * indicates the first instruction that would be returned by an initial call
	 * to the <code>next</code> method. An initial call to the <code>previous</code>
	 * method would return the instruction with an address less than the
	 * specified address.
	 * <p>
	 *
	 * @param addr the initial position of the iterator
	 * @param forward true means get iterator in forward direction
	 * @return an InstructionIterator that iterates over all Instruction objects
	 *         in the given address range set.
	 */
	public InstructionIterator getInstructions(Address addr, boolean forward);

	/**
	 * Get an Instruction iterator over the address range(s). Only instructions
	 * whose start addresses are contained in the given address set will be
	 * returned by the iterator.
	 *
	 * @param addrSet the address range set to iterate over.
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined and undefined Data
	 *         objects in the given address range set.
	 */
	public InstructionIterator getInstructions(AddressSetView addrSet, boolean forward);

	/**
	 * get the Data (Defined or Undefined) that starts at the given address.
	 *
	 * @param addr the address to check for a Data object.
	 * @return the Data object that starts at addr; or null if no Data
	 *         objects(defined or undefined) start at addr.
	 */
	public Data getDataAt(Address addr);

	/**
	 * Gets the data object that is at or contains the given address or null if
	 * the address in not in memory or is in an instruction.
	 *
	 * @param addr the address for which to find its containing data element.
	 * @return the Data object containing the given address or null if there is
	 *         no data that contains the address.
	 */
	public Data getDataContaining(Address addr);

	/**
	 * get the closest Data object that starts at an address that is greater
	 * than the given address.
	 *
	 * @param addr the address at which to begin the forward search.
	 * @return the next Data object whose starting address is greater than addr.
	 */
	public Data getDataAfter(Address addr);

	/**
	 * get the closest Data object that starts at an address that is less than
	 * the given address.
	 *
	 * @param addr The address at which to begin the backward search.
	 * @return the closest Data object whose starting address is less than addr.
	 */
	public Data getDataBefore(Address addr);

	/**
	 * get a Data iterator that will iterate over the entire address space;
	 * returning both defined and undefined Data objects.
	 *
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined and undefined Data
	 *         object in the program.
	 */
	public DataIterator getData(boolean forward);

	/**
	 * Returns an iterator of the data in this listing (in proper sequence),
	 * starting at the specified address. The specified address indicates the
	 * first Data that would be returned by an initial call to the <code>next</code>
	 * method. An initial call to the <code>previous</code> method would return the
	 * Data with an address less than the specified address.
	 * <p>
	 *
	 * @param addr the initial position of the iterator
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all Data objects in the given
	 *         address range set.
	 */
	public DataIterator getData(Address addr, boolean forward);

	/**
	 * Get an iterator over the address range(s). Only data whose start
	 * addresses are contained in the given address set will be returned by the
	 * iterator.
	 *
	 * @param addrSet the address range set to iterate over.
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined and undefined Data
	 *         objects in the given address range set.
	 */
	public DataIterator getData(AddressSetView addrSet, boolean forward);

	/**
	 * get the Data (defined) object that starts at the given address. If no
	 * Data object is defined at that address, then return null.
	 *
	 * @param addr The address to check for defined Data.
	 * @return a Data object that starts at addr, or null if no Data object has
	 *         been defined to start at addr.
	 */
	public Data getDefinedDataAt(Address addr);

	/**
	 * get the Data object that starts at the given address. If no Data objects
	 * have been defined that contain that address, then return null.
	 *
	 * @param addr the address to check for containment in a defined Data
	 *            object.
	 * @return the defined Data object containing addr.
	 */
	public Data getDefinedDataContaining(Address addr);

	/**
	 *
	 * get the defined Data object that starts at an address that is greater
	 * than the given address.
	 *
	 * @param addr the address at which to begin the forward search.
	 * @return the next defined Data object whose starting address is greater
	 *         than addr.
	 */
	public Data getDefinedDataAfter(Address addr);

	/**
	 * get the closest defined Data object that starts at an address that is
	 * less than the given address.
	 *
	 * @param addr The address at which to begin the backward search.
	 * @return the closest defined Data object whose starting address is less
	 *         than addr.
	 */
	public Data getDefinedDataBefore(Address addr);

	/**
	 * get a Data iterator that will iterate over the entire address space;
	 * returning only defined Data objects.
	 *
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined Data objects in the
	 *         program.
	 */
	public DataIterator getDefinedData(boolean forward);

	/**
	 * Returns an iterator of the defined data in this listing (in proper
	 * sequence), starting at the specified address. The specified address
	 * indicates the first defined Data that would be returned by an initial
	 * call to the <code>next</code> method. An initial call to the
	 * <code>previous</code> method would return the defined Data with an address
	 * less than the specified address.
	 * <p>
	 *
	 * @param addr the initial position of the iterator
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined Data objects in the
	 *         given address range set.
	 */
	public DataIterator getDefinedData(Address addr, boolean forward);

	/**
	 * Get an iterator over the address range(s). Only defined data whose start
	 * addresses are contained in the given address set will be returned by the
	 * iterator.
	 *
	 * @param addrSet the address range set to iterate over.
	 * @param forward true means get iterator in forward direction
	 * @return a DataIterator that iterates over all defined Data objects in the
	 *         given address range set.
	 */
	public DataIterator getDefinedData(AddressSetView addrSet, boolean forward);

	/**
	 * get the Data (undefined) object that starts at the given address.
	 *
	 * @param addr The address to check for undefined data.
	 * @return a default DataObject if bytes exist at addr and nothing has been
	 *         defined to exist there. Otherwise returns null.
	 */
	public Data getUndefinedDataAt(Address addr);

	/**
	 * Get the undefined Data object that starts at an address that is greater
	 * than the given address. This operation can be slow for large programs so
	 * a TaskMonitor is required.
	 *
	 * @param addr the address at which to begin the forward search.
	 * @param monitor a task monitor allowing this operation to be cancelled
	 * @return the next undefined Data object whose starting address is greater
	 *         than addr.
	 */
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor);

	/**
	 * Get the undefined Data object that falls within the set. This operation
	 * can be slow for large programs so a TaskMonitor is required.
	 *
	 * @param set the addressSet at which to find the first undefined address.
	 * @param monitor a task monitor allowing this operation to be cancelled
	 *
	 * @return the next undefined Data object whose starting address falls
	 *         within the addresSet.
	 */
	public Data getFirstUndefinedData(AddressSetView set, TaskMonitor monitor);

	/**
	 * get the closest undefined Data object that starts at an address that is
	 * less than the given address. This operation can be slow for large
	 * programs so a TaskMonitor is required.
	 *
	 * @param addr The address at which to begin the backward search.
	 * @param monitor a task monitor allowing this operation to be cancelled
	 * @return the closest undefined Data object whose starting address is less
	 *         than addr.
	 */
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor);

	/**
	 * Get the address set which corresponds to all undefined code units within
	 * the specified set of address.
	 *
	 * @param set set of addresses to search
	 * @param initializedMemoryOnly if true set will be constrained to
	 *            initialized memory areas, if false set will be constrained to
	 *            all defined memory blocks.
	 * @param monitor task monitor
	 * @return address set corresponding to undefined code units
	 * @throws CancelledException if monitor cancelled
	 */
	public AddressSetView getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns the next instruction or defined data after the given address;
	 *
	 * @param addr the address at which to begin the search
	 * @return the next instruction or defined data at an address higher than
	 *         the given address.
	 */
	public CodeUnit getDefinedCodeUnitAfter(Address addr);

	/**
	 * Returns the closest instruction or defined data that starts before the
	 * given address.
	 *
	 * @param addr the address at which to begin the search
	 * @return the closest instruction or defined data at an address below the
	 *         given address.
	 */
	public CodeUnit getDefinedCodeUnitBefore(Address addr);

	/**
	 * Get an iterator over all the composite data objects (Arrays, Structures,
	 * and Union) in the program.
	 *
	 * @param forward true means get iterator that starts at the minimum address
	 *            and iterates forward. Otherwise it starts at the maximum
	 *            address and iterates backwards.
	 * @return an iterator over all the composite data objects.
	 */
	public DataIterator getCompositeData(boolean forward);

	/**
	 * Get an iterator over all the composite data objects (Arrays, Structures,
	 * and Union) in the program at or after the given Address.
	 *
	 * @param start start of the iterator
	 * @param forward true means get iterator in forward direction
	 * @return an iterator over all the composite data objects starting with the
	 *         given address.
	 */
	public DataIterator getCompositeData(Address start, boolean forward);

	/**
	 * Get an iterator over all the composite data objects (Arrays, Structures,
	 * and Union) within the specified address set in the program.
	 *
	 * @param addrSet the address set
	 * @param forward true means get iterator in forward direction
	 * @return an iterator over all the composite data objects in the given
	 *         address set.
	 */
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward);

	/**
	 * Returns an iterator over all user defined property names.
	 *
	 * @return an iterator over all user defined property names.
	 */
	public Iterator<String> getUserDefinedProperties();

	/**
	 * Removes the entire property from the program
	 *
	 * @param propertyName the name of the property to remove.
	 */
	public void removeUserDefinedProperty(String propertyName);

	/**
	 * Returns the PropertyMap associated with the given name
	 *
	 * @param propertyName the property name
	 * @return PropertyMap the propertyMap object.
	 */
	public PropertyMap getPropertyMap(String propertyName);

	/**
	 * Creates a new Instruction object at the given address. The specified
	 * context is only used to create the associated prototype. It is critical
	 * that the context be written immediately after creation of the instruction
	 * and must be done with a single set operation on the program context. Once
	 * a set context is done on the instruction address, any subsequent context
	 * changes will result in a <code>ContextChangeException</code>
	 *
	 * @param addr the address at which to create an instruction
	 * @param prototype the InstructionPrototype the describes the type of
	 *            instruction to create.
	 * @param memBuf buffer that provides the bytes that make up the
	 *            instruction.
	 * @param context the processor context at this location.
	 * @return the newly created instruction.
	 * @exception CodeUnitInsertionException thrown if the new Instruction would
	 *                overlap and existing Instruction or defined data.
	 */
	public Instruction createInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException;

	/**
	 * Creates a complete set of instructions. A preliminary pass will be made
	 * checking for code unit conflicts which will be marked within the
	 * instructionSet causing dependent blocks to get pruned.
	 * 
	 * @param instructionSet the set of instructions to be added. All code unit
	 *            conflicts will be marked within the instructionSet and
	 *            associated blocks.
	 * @param overwrite if true, overwrites existing code units.
	 * @throws CodeUnitInsertionException if the instruction set is incompatible
	 *             with the program memory
	 * @return the set of addresses over which instructions were actually added
	 *         to the program. This may differ from the InstructionSet address
	 *         set if conflict errors occurred. Such conflict errors will be
	 *         recorded within the InstructionSet and its InstructionBlocks.
	 */
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite)
			throws CodeUnitInsertionException;

	/**
	 * Creates a new defined Data object of a given length at the given address.
	 * This ignores the bytes that are present
	 *
	 * @param addr the address at which to create a new Data object.
	 * @param dataType the Data Type that describes the type of Data object to
	 *            create.
	 * @param length the length of the datatype.
	 * @return newly created data unit
	 * @exception CodeUnitInsertionException thrown if the new Instruction would
	 *                overlap and existing Instruction or defined data.
	 * @throws DataTypeConflictException if the given datatype conflicts (same
	 *             name, but not equal) with an existing datatype.
	 */
	public Data createData(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException, DataTypeConflictException;

	/**
	 * Creates a new defined Data object at the given address. This ignores the
	 * bytes that are present
	 *
	 * @param addr the address at which to create a new Data object.
	 * @param dataType the Data Type that describes the type of Data object to
	 *            create.
	 * @return newly created data unit
	 * @exception CodeUnitInsertionException thrown if the new Instruction would
	 *                overlap and existing Instruction or defined data.
	 * @throws DataTypeConflictException if the given datatype conflicts (same
	 *             name, but not equal) with an existing datatype.
	 */
	public Data createData(Address addr, DataType dataType)
			throws CodeUnitInsertionException, DataTypeConflictException;

	/**
	 * Clears any code units in the given range returning everything to "db"s,
	 * and removing any references in the affected area. Note that the module
	 * and fragment structure is unaffected. If part of a code unit is contained
	 * in the given address range then the whole code unit will be cleared.
	 *
	 * @param startAddr the start address of the area to be cleared.
	 * @param endAddr the end address of the area to be cleared.
	 * @param clearContext clear context register values if true
	 */
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext);

	/**
	 * Clears any code units in the given range returning everything to "db"s,
	 * and removing any references in the affected area. Note that the module
	 * and fragment structure is unaffected. If part of a code unit is contained
	 * in the given address range then the whole code unit will be cleared.
	 *
	 * @param startAddr the start address of the area to be cleared.
	 * @param endAddr the end address of the area to be cleared.
	 * @param clearContext clear context register values if true
	 * @param monitor monitor that can be used to cancel the clear operation
	 * @throws CancelledException if the operation was cancelled.
	 */
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * Checks if the given ranges consists entirely of undefined data.
	 * 
	 * @param start The start address of the range to check.
	 * @param end The end address of the range to check.
	 * @return boolean true if the given range is in memory and has no
	 *         instructions or defined data.
	 */
	public boolean isUndefined(Address start, Address end);

	/**
	 * Clears the comments in the given range.
	 * 
	 * @param startAddr the start address of the range to be cleared
	 * @param endAddr the end address of the range to be cleard
	 */
	public void clearComments(Address startAddr, Address endAddr);

	/**
	 * Clears the properties in the given range.
	 * 
	 * @param startAddr the start address of the range to be cleared
	 * @param endAddr the end address of the range to be cleard
	 * @param monitor task monitor for cancelling operation.
	 * @throws CancelledException if the operation was cancelled.
	 */
	public void clearProperties(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Removes all CodeUnits, comments, properties, and references from the
	 * listing.
	 * 
	 * @param clearContext if true, also clear any instruction context that has
	 *            been laid down from previous disassembly.
	 * @param monitor used for tracking progress and cancelling the clear
	 *            operation.
	 */
	public void clearAll(boolean clearContext, TaskMonitor monitor);

	/**
	 * Returns the fragment containing the given address.
	 * <P>
	 * 
	 * @param treeName name of the tree to search
	 * @param addr the address that is contained within a fragment.
	 *
	 * @return will return null if the address is not in the program.
	 */
	public ProgramFragment getFragment(String treeName, Address addr);

	/**
	 * Returns the module with the given name.
	 * <P>
	 * 
	 * @param treeName name of the tree to search
	 * @param name the name of the module to find.
	 *
	 * @return will return null if there is no module with the given name.
	 */
	public ProgramModule getModule(String treeName, String name);

	/**
	 * Returns the fragment with the given name.
	 * <P>
	 * 
	 * @param treeName name of the tree to search
	 * @param name the name of the fragment to find.
	 *
	 * @return will return null if there is no fragment with the given name.
	 */
	public ProgramFragment getFragment(String treeName, String name);

	/**
	 * Create a new tree that will be identified by the given name. By default,
	 * the new root module is populated with fragments based on memory blocks.
	 * Note that the root module's name is not the same as its tree name. The
	 * root module name defaults to the name of the program.
	 * 
	 * @param treeName name of the tree to search
	 * @return root module
	 * @throws DuplicateNameException if a tree with the given name already
	 *             exists
	 */
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException;

	/**
	 * Gets the root module for a tree in this listing.
	 * 
	 * @param treeName name of tree
	 *
	 * @return the root module for the listing; returns null if there is no tree
	 *         rooted at a module with the given name.
	 */
	public ProgramModule getRootModule(String treeName);

	/**
	 * Returns the root module of the program tree with the given name;
	 * 
	 * @param treeID id of the program tree
	 * @return the root module of the specified tree.
	 */
	public ProgramModule getRootModule(long treeID);

	/**
	 * Returns the root module for the default program tree. This would be the
	 * program tree that has existed the longest.
	 *
	 * @return the root module for the oldest existing program tree.
	 */
	public ProgramModule getDefaultRootModule();

	/**
	 * Get the names of all the trees defined in this listing.
	 *
	 * @return the names of all program trees defined in the program.
	 */
	public String[] getTreeNames();

	/**
	 * Remove the tree rooted at the given name.
	 * 
	 * @param treeName the name of the tree to remove.
	 * @return true if the tree was removed; return false if this is the last
	 *         tree for the program; cannot delete the last tree.
	 */
	public boolean removeTree(String treeName);

	/**
	 * Rename the tree. This method does not change the root module's name only
	 * the identifier for the tree.
	 * 
	 * @param oldName old name of the tree
	 * @param newName new name of the tree.
	 * @throws DuplicateNameException if newName already exists for a root
	 *             module
	 */
	public void renameTree(String oldName, String newName) throws DuplicateNameException;

	/**
	 * gets the total number of CodeUnits (Instructions, defined Data, and
	 * undefined Data)
	 *
	 * @return the total number of CodeUnits in the listing.
	 */
	public long getNumCodeUnits();

	/**
	 * gets the total number of defined Data objects in the listing.
	 *
	 * @return the total number of defined Data objects in the listing.
	 */
	public long getNumDefinedData();

	/**
	 * gets the total number of Instructions in the listing.
	 *
	 * @return number of Instructions
	 */
	public long getNumInstructions();

	/**
	 * Get the data type manager for the program.
	 * 
	 * @return the datatype manager for the program.
	 */
	public DataTypeManager getDataTypeManager();

	/**
	 * Create a function with an entry point and a body of addresses.
	 * 
	 * @param name the name of the function to create
	 * @param entryPoint the entry point for the function
	 * @param body the address set that makes up the functions body
	 * @param source the source of this function
	 * @return the created function
	 * @throws InvalidInputException if the name contains invalid characters
	 * @throws OverlappingFunctionException if the given body overlaps with an
	 *             existing function.
	 */
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException;

	/**
	 * Create a function in the specified namespace with an entry point and a
	 * body of addresses.
	 * 
	 * @param name the name of the function to create
	 * @param nameSpace the namespace in which to create the function
	 * @param entryPoint the entry point for the function
	 * @param body the address set that makes up the functions body
	 * @param source the source of this function
	 * @return the created function
	 * @throws InvalidInputException if the name contains invalid characters
	 * @throws OverlappingFunctionException if the given body overlaps with an
	 *             existing function.
	 */
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException;

	/**
	 * Remove a function a given entry point.
	 *
	 * @param entryPoint entry point of function to be removed.
	 */
	public void removeFunction(Address entryPoint);

	/**
	 * Get a function with a given entry point.
	 *
	 * @param entryPoint entry point of the function
	 * @return function at the entry point
	 */
	public Function getFunctionAt(Address entryPoint);

	/**
	 * Returns a list of all global functions with the given name.
	 * 
	 * @param name the name of the functions to retrieve.
	 * @return a list of all global functions with the given name.
	 */
	public List<Function> getGlobalFunctions(String name);

	/**
	 * Returns a list of all functions with the given name in the given
	 * namespace.
	 * 
	 * @param namespace the namespace to search for functions of the given name.
	 *            Can be null, in which case it will search the global
	 *            namespace.
	 * @param name the name of the functions to retrieve.
	 * @return a list of all global functions with the given name.
	 */
	public List<Function> getFunctions(String namespace, String name);

	/**
	 * Get a function containing an address.
	 * 
	 * @param addr the address to search.
	 * @return function containing this address, null otherwise
	 */
	public Function getFunctionContaining(Address addr);

	/**
	 * Get an iterator over all external functions
	 * 
	 * @return an iterator over all currently defined external functions.
	 */
	public FunctionIterator getExternalFunctions();

	/**
	 * Get an iterator over all functions
	 * 
	 * @param forward if true functions are return in address order, otherwise
	 *            backwards address order
	 * @return an iterator over all currently defined functions.
	 */
	public FunctionIterator getFunctions(boolean forward);

	/**
	 * Get an iterator over all functions starting at address
	 * 
	 * @param start the address to start iterating at.
	 * @param forward if true functions are return in address order, otherwise
	 *            backwards address order
	 * @return an iterator over functions
	 */
	public FunctionIterator getFunctions(Address start, boolean forward);

	/**
	 * Get an iterator over all functions with entry points in the address set.
	 * 
	 * @param asv the set of addresses to iterator function entry points over.
	 * @param forward if true functions are return in address order, otherwise
	 *            backwards address order
	 * @return an iterator over functions
	 */
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward);

	/**
	 * Check if an address is contained in a function
	 *
	 * @param addr address to test
	 * @return true if this address is in one or more functions
	 */
	public boolean isInFunction(Address addr);

	/**
	 * Get the comment history for comments at the given address.
	 * 
	 * @param addr address for comments
	 * @param commentType comment type defined in CodeUnit
	 * @return array of comment history records
	 */
	public CommentHistory[] getCommentHistory(Address addr, int commentType);

}
