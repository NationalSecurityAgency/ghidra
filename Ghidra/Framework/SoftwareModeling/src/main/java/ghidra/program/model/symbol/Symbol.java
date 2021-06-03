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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Interface for a symbol, which associates a string value with
 * an address.
 */
public interface Symbol {

	/**
	 * @return the address for the symbol.
	 */
	public Address getAddress();

	/**
	 * @return the name of this symbol.
	 */
	public String getName();

	/**
	 * Gets the full path name for this symbol as an ordered array of strings ending
	 * with the symbol name. The global symbol will return an empty array.
	 * @return the array indicating the full path name for this symbol.
	 */
	public String[] getPath();

	/**
	 * @return the program associated with this symbol.
	 * Null may be returned for global symbols.
	 */
	public Program getProgram();

	/**
	 * Returns the symbol name, optionally prepended with the namespace path.
	 * @param includeNamespace if true, the namespace path is prepended to the name.
	 * @return formatted name
	 */
	public String getName(boolean includeNamespace);

	/**
	 * Return the parent namespace for this symbol.
	 * @return the namespace that contains this symbol.
	 */
	public Namespace getParentNamespace();

	/**
	 * Returns namespace symbol of the namespace containing this symbol
	 * @return parent namespace symbol
	 */
	public Symbol getParentSymbol();

	/**
	 * Returns true if the given namespace symbol is a descendant of this symbol.
	 * @param namespace to test as descendant symbol of this Symbol
	 * @return true if this symbol is an ancestor of the given namespace symbol
	 */
	public boolean isDescendant(Namespace namespace);

	/**
	 * Determines if the given parent is valid for this Symbol.  Specified namespace 
	 * must belong to the same symbol table as this symbol.
	 * @param parent prospective parent namespace for this symbol
	 * @return true if parent is valid
	 */
	public boolean isValidParent(Namespace parent);

	/**
	 * Returns this symbol's type
	 * @return symbol type
	 */
	public SymbolType getSymbolType();

	/**
	 * @return the number of References to this symbol.
	 */
	public int getReferenceCount();

	/**
	 * @return true if this symbol has more than one reference to it.
	 */
	public boolean hasMultipleReferences();

	/**
	 * @return true if this symbol has at least one reference to it.
	 */
	public boolean hasReferences();

	/**
	 * Returns all memory references to the address of this symbol.  If you do not have a
	 * {@link TaskMonitor} instance, then you can pass {@link TaskMonitorAdapter#DUMMY_MONITOR} or
	 * <code>null</code>.
	 *
	 * @return all memory references to the address of this symbol.
	 *
	 * @param monitor the monitor that is used to report progress and to cancel this
	 *        potentially long-running call
	 */
	public Reference[] getReferences(TaskMonitor monitor);

	/**
	 * Returns all memory references to the address of this symbol.
	 *
	 * @return all memory references to the address of this symbol
	 * @see #getReferences(TaskMonitor)
	 */
	public Reference[] getReferences();

	/**
	 * @return a program location corresponding to this symbol
	 */
	public ProgramLocation getProgramLocation();

	/**
	 * Sets the name this symbol.
	 * If this symbol is dynamic, then the name is set
	 * and the symbol is no longer dynamic.
	 * @param newName the new name for this symbol.
	 * @param source the source of this symbol
	 * <br>Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
	 *
	 * @throws DuplicateNameException
	 * 		if name already exists as the name of another symbol or alias.
	 * @throws InvalidInputException
	 * 		if alias contains blank characters, is zero length, or is null
	 * @throws IllegalArgumentException if you try to set the source to DEFAULT for a symbol type
	 * that doesn't allow it.
	 */
	public void setName(String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Sets the symbols namespace
	 * @param newNamespace new parent namespace
	 * @throws DuplicateNameException if newNamespace already contains a symbol
	 * with this symbol's name
	 * @throws InvalidInputException is newNamespace is not a valid parent for
	 * this symbol
	 * @throws CircularDependencyException if this symbol is an ancestor of
	 * newNamespace
	 */
	public void setNamespace(Namespace newNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException;

	/**
	 * Sets the symbols name and namespace.  This is provided to allow the caller to
	 * avoid a name conflict by creating an autonomous action.
	 * @param newName new symbol name
	 * @param newNamespace new parent namespace
	 * @param source the source of this symbol
	 * <br>Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
	 *
	 * @throws DuplicateNameException if newNamespace already contains a symbol
	 * with this symbol's name
	 * @throws InvalidInputException is newNamespace is not a valid parent for
	 * this symbol
	 * @throws CircularDependencyException if this symbol is an ancestor of
	 * newNamespace
	 */
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException;

	/**
	 * Delete the symbol and its associated resources.
	 * @return true if successful
	 */
	public boolean delete();

	/**
	 * Returns true if the symbol is pinned to its current address. If it is pinned, then moving
	 * or removing the memory associated with that address will not affect this symbol.
	 *
	 * @return true if the symbol is pinned to its current address.
	 */
	public boolean isPinned();

	/**
	 * <p>Sets whether or not this symbol is pinned to its associated address.</p>
	 *
	 * <p>If the symbol is pinned then moving or removing the memory associated with its address will
	 * not cause this symbol to be removed and will not cause its address to change.
	 * If the symbol is not pinned, then removing the memory at its address will also remove this
	 * symbol.</p>
	 *
	 * <p>Likewise, moving a memory block containing a symbol that is not anchored will change
	 * the address for that symbol to keep it associated with the same byte in the memory block.</p>
	 *
	 * @param pinned true indicates this symbol is anchored to its address.
	 * 		false indicates this symbol is not anchored to its address.
	 */
	public void setPinned(boolean pinned);

	/**
	 * @return true if this symbol is a dynamic symbol (not actually defined in the database).
	 */
	public boolean isDynamic();

	/**
	 * Returns true if this an external symbol.
	 *
	 * @return true if this an external symbol.
	 * @see Address#isExternalAddress()
	 */
	public boolean isExternal();

	/**
	 * @return true if this symbol is primary
	 */
	public boolean isPrimary();

	/**
	 * Sets this symbol to be primary. All other symbols at the same address will be set to 
	 * !primary.  Only applies to non-function symbols.
	 * @return returns true if the symbol was not primary and now it is, otherwise false
	 */
	public boolean setPrimary();

	/**
	 * @return true if the symbol is at an address
	 * set as a external entry point.
	 */
	public boolean isExternalEntryPoint();

	/**
	 * @return this symbol's ID.
	 */
	public long getID();

	/**
	 * @return object associated with this symbol or null if symbol has been deleted
	 */
	public Object getObject();

	/**
	 * @return true if the symbol is global
	 */
	public boolean isGlobal();

	/**
	 * Sets the source of this symbol.
	 * {@link SourceType}
	 * @param source the new source of this symbol
	 */
	public void setSource(SourceType source);

	/**
	 * Gets the source of this symbol.
	 * {@link SourceType}
	 * @return the source of this symbol
	 */
	public SourceType getSource();

	/**
	 * Determine if this symbol object has been deleted.  NOTE: the symbol could be
	 * deleted at anytime due to asynchronous activity.  
	 * @return true if symbol has been deleted, false if not.
	 */
	public boolean isDeleted();
}
