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

import ghidra.program.database.ManagerDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * The manager for functions
 */
public interface FunctionManager extends ManagerDB {

	/**
	 * Returns this manager's program
	 * @return the program
	 */
	public Program getProgram();

	/**
	 * Gets the names associated with each of the current calling conventions associated with this
	 * program. Within the exception of "unknown", all of these calling convention names should have
	 * a PrototypeModel.
	 *
	 * @return the calling convention names.
	 */
	public List<String> getCallingConventionNames();

	/**
	 * Gets the default calling convention's prototype model in this program.
	 *
	 * @return the default calling convention prototype model or null.
	 */
	public PrototypeModel getDefaultCallingConvention();

	/**
	 * Gets the prototype model of the calling convention with the specified name in this program
	 * @param name the calling convention name
	 * @return the named function calling convention prototype model or null.
	 */
	public PrototypeModel getCallingConvention(String name);

	/**
	 * Gets all the calling convention prototype models in this program that have names.
	 *
	 * @return the function calling convention prototype models.
	 */
	public PrototypeModel[] getCallingConventions();

	/**
	 * Create a function with the given body at entry point within the global namespace.
	 *
	 * @param name the name of the new function or null for default name
	 * @param entryPoint entry point of function
	 * @param body addresses contained in the function body
	 * @param source the source of this function
	 * @return new function or null if one or more functions overlap the specified body address set.
	 * @throws InvalidInputException if the name has invalid characters
	 * @throws OverlappingFunctionException if the address set of the body overlaps an existing
	 *             function
	 */
	public Function createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException;

	/**
	 * Create a function with the given body at entry point.
	 *
	 * @param name the name of the new function or null for default name
	 * @param nameSpace the nameSpace in which to create the function
	 * @param entryPoint entry point of function
	 * @param body addresses contained in the function body
	 * @param source the source of this function
	 * @return new function or null if one or more functions overlap the specified body address set.
	 * @throws InvalidInputException if the name has invalid characters
	 * @throws OverlappingFunctionException if the address set of the body overlaps an existing
	 *             function
	 */
	public Function createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException;

	/**
	 * Create a thunk function with the given body at entry point.
	 *
	 * @param name the name of the new function or null for default name
	 * @param nameSpace the nameSpace in which to create the function
	 * @param entryPoint entry point of function
	 * @param body addresses contained in the function body
	 * @param thunkedFunction referenced function (required is creating a thunk function)
	 * @param source the source of this function
	 * @return new function or null if one or more functions overlap the specified body address set.
	 * @throws OverlappingFunctionException if the address set of the body overlaps an existing
	 *             function
	 */
	public Function createThunkFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, Function thunkedFunction, SourceType source)
			throws OverlappingFunctionException;

	/**
	 * Returns the total number of functions in the program including external functions
	 * @return the count
	 */
	public int getFunctionCount();

	/**
	 * Remove a function defined at entryPoint
	 * @param entryPoint the entry point
	 * @return true if the function was removed
	 */
	public boolean removeFunction(Address entryPoint);

	/**
	 * Get the function at entryPoint
	 * @param entryPoint the entry point
	 * @return null if there is no function at entryPoint
	 */
	public Function getFunctionAt(Address entryPoint);

	/**
	 * Get the function which resides at the specified address or is referenced from the specified 
	 * address
	 *
	 * @param address function address or address of pointer to a function.
	 * @return referenced function or null
	 */
	public Function getReferencedFunction(Address address);

	/**
	 * Get a function containing an address.
	 *
	 * @param addr address within the function
	 * @return function containing this address, null otherwise
	 */
	public Function getFunctionContaining(Address addr);

	/**
	 * Returns an iterator over all non-external functions in address (entry point) order
	 * @param forward true means to iterate in ascending address order
	 * @return the iterator
	 */
	public FunctionIterator getFunctions(boolean forward);

	/**
	 * Get an iterator over non-external functions starting at an address and ordered by entry
	 * address
	 *
	 * @param start starting address
	 * @param forward true means to iterate in ascending address order
	 * @return an iterator over functions.
	 */
	public FunctionIterator getFunctions(Address start, boolean forward);

	/**
	 * Get an iterator over functions with entry points in the specified address set. Function are
	 * ordered based upon entry address.
	 *
	 * @param asv address set to iterate over
	 * @param forward true means to iterate in ascending address order
	 * @return an iterator over functions.
	 */
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward);

	/**
	 * Returns an iterator over all REAL functions in address (entry point) order (real functions
	 * have instructions, and aren't stubs)
	 *
	 * @param forward true means to iterate in ascending address order
	 * @return the iterator
	 */
	public FunctionIterator getFunctionsNoStubs(boolean forward);

	/**
	 * Get an iterator over REAL functions starting at an address and ordered by entry address (real
	 * functions have instructions, and aren't stubs).
	 *
	 * @param start starting address
	 * @param forward true means to iterate in ascending address order
	 *
	 * @return an iterator over functions.
	 */
	public FunctionIterator getFunctionsNoStubs(Address start, boolean forward);

	/**
	 * Get an iterator over REAL functions with entry points in the specified address set (real
	 * functions have instructions, and aren't stubs). Functions are ordered based upon entry
	 * address.
	 *
	 * @param asv address set to iterate over
	 * @param forward true means to iterate in ascending address order
	 * @return an iterator over functions.
	 */
	public FunctionIterator getFunctionsNoStubs(AddressSetView asv, boolean forward);

	/**
	 * Get an iterator over all external functions. Functions returned have no particular order.
	 *
	 * @return an iterator over external functions
	 */
	public FunctionIterator getExternalFunctions();

	/**
	 * Check if this address contains a function.
	 *
	 * @param addr address to check
	 *
	 * @return true if this address is contained in a function.
	 */
	public boolean isInFunction(Address addr);

	/**
	 * Return an iterator over functions that overlap the given address set.
	 *
	 * @param set address set of interest
	 * @return iterator over Functions
	 */
	public Iterator<Function> getFunctionsOverlapping(AddressSetView set);

	/**
	 * Attempts to determine which if any of the local functions variables are referenced by the
	 * specified reference. In utilizing the firstUseOffset scoping model, negative offsets
	 * (relative to the functions entry) are shifted beyond the maximum positive offset within the
	 * function. While this does not account for the actual instruction flow, it is hopefully
	 * accurate enough for most situations.
	 *
	 * @param instrAddr the instruction address
	 * @param storageAddr the storage address
	 * @param size varnode size in bytes (1 is assumed if value &lt;= 0)
	 * @param isRead true if the reference is a read reference
	 * @return referenced variable or null if one not found
	 */
	public Variable getReferencedVariable(Address instrAddr, Address storageAddr, int size,
			boolean isRead);

	/**
	 * Get a Function object by its key
	 * @param key function symbol key
	 * @return function object or null if not found
	 */
	public Function getFunction(long key);

	/**
	 * Returns the function tag manager
	 * @return the function tag manager
	 */
	public FunctionTagManager getFunctionTagManager();

	/**
	 * Clears all data caches
	 * @param all if false, some managers may not need to update their cache if they can
	 * tell that its not necessary.  If this flag is true, then all managers should clear
	 * their cache no matter what.
	 */
	@Override
	public void invalidateCache(boolean all); // note: redeclared to not throw an exception

	/**
	 * Move all objects within an address range to a new location
	 * @param fromAddr the first address of the range to be moved
	 * @param toAddr the address where to the range is to be moved
	 * @param length the number of addresses to move
	 * @param monitor the task monitor to use in any upgrade operations
	 * @throws CancelledException if the user cancelled the operation via the task monitor
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException; // note: redeclared to not throw an AddressOverflowException
}
