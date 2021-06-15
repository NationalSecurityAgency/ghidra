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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * A SymbolTable manages the Symbols defined in a program.
 * <br>
 * A Symbol is an association between an Address,
 * a String name. In addition, symbols may have one or more
 * References.
 * <br>
 * A Reference is a 4-tuple of a source address, destination address, type,
 * and either a mnemonic or operand index
 * <br>
 * Any address in a program can have more than one symbol associated to it.
 * At any given time, one and only one symbol will be designated as the primary.
 * <br>
 * A symbol can be either global or local. Local symbols belong to some namespace other than
 * the global namespace.
 * <br>
 * Label and Function symbols do not have to have unique names with a namespace. All other symbols
 * must be unique within a namespace and be unique with all other symbols that must be unique.
 * In other words you can have a several functions named "foo" and several labels named "foo"
 * in the same namespace.  But you can't have a class named "foo" and a namespace named "foo".
 * But you can have a class named "foo" and and many functions and labels named "foo" all
 * in the same namespace.
 * <br>
 * A symbol can also be designated as dynamic. Which means the name is
 * generated on-the-fly by the system based on its context.
 */
public interface SymbolTable {

	/**
	 * Create a label symbol with the given name associated to the given
	 * Address. The symbol will be global and be of type SymbolType.CODE. Label
	 * Symbols do not have to have unique names.
	 * If this is the first symbol defined for the address it becomes
	 * the primary.
	 * @param addr the address at which to create a symbol
	 * @param name the name of the symbol.
	 * @param source the source of this symbol
	 * <br>Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
	 * @return new code or function symbol
	 * @throws InvalidInputException thrown if names contains white space, is zero length, or is
	 * null for non-default source.
	 * @throws IllegalArgumentException if you try to set the source to DEFAULT for a symbol type
	 * that doesn't allow it, or an improper addr is specified
	 */
	public Symbol createLabel(Address addr, String name, SourceType source)
			throws InvalidInputException;

	/**
	 * @deprecated use {@link #createLabel(Address, String, SourceType)} instead.
	 * Deprecated in version 7.5, will be removed a few versions later.
	 */
	@Deprecated
	public Symbol createSymbol(Address addr, String name, SourceType source)
			throws InvalidInputException;

	/**
	 * Create a label symbol with the given name associated to the given
	 * Address and namespace. The symbol will be of type SymbolType.CODE.
	 * If this is the first symbol defined for the address it becomes
	 * the primary symbol.  If a symbol with that name already exists at the
	 * address, it will be returned instead with its namespace changed to the new
	 * namespace unless the new symbol is in the global space, in which case the namespace
	 * will remain as is.
	 * @param addr the address at which to create a symbol
	 * @param name the name of the symbol.
	 * @param namespace the namespace of the symbol.
	 * @param source the source of this symbol
	 * <br>Some symbol types, such as function symbols, can set the source to Symbol.DEFAULT.
	 * @return new code or function symbol
	 * @throws InvalidInputException thrown if names contains white space, is zero length, or is
	 * null for non-default source.  Also thrown if invalid parentNamespace is specified.
	 * @throws IllegalArgumentException if you try to set the source to DEFAULT for a symbol type
	 * that doesn't allow it, or an improper addr is specified
	 */
	public Symbol createLabel(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException;

	/**
	 * @deprecated use {@link #createLabel(Address, String, Namespace, SourceType)} instead.
	 * Deprecated in version 7.5, will be removed a few versions later.
	 */
	@Deprecated
	public Symbol createSymbol(Address addr, String name, Namespace namespace, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Removes the specified symbol from the symbol table.  If removing any <b>non-function</b>
	 * symbol the behavior will be the same as invoking {@link Symbol#delete()} on the
	 * symbol.  Use of this method for non-function symbols is discouraged.
	 * <p>
	 * <b>WARNING!</b> If removing a function symbol the behavior differs from directly
	 * invoking {@link Symbol#delete()} on the function symbol.
	 * <p>
	 * When removing a function symbol this method has the following behavior:
	 * <ul>
	 * <li>If the function is a default symbol (e.g., FUN_12345678) this method
	 * has no affect and will return null</li>
	 * <li>otherwise if another label exists at the function entry point, that
	 * label will be removed and the function will be renamed with that labels name</li>
	 * <li>If no other labels exist at the function entry, the function will
	 * be renamed to the default function name</li>
	 * </ul>
	 * Any reference bound to a symbol removed will loose that
	 * symbol specific binding.
	 *
	 * @param sym the symbol to be removed.
	 *
	 * @return false, if removal of the symbol fails
	 */
	public boolean removeSymbolSpecial(Symbol sym);

//	/**
//	 * This method is just a pass-through for {@link #removeSymbolSpecial(Symbol)}.
//	 *
//	 * @see #removeSymbolSpecial(Symbol)
//	 * @deprecated Call instead {@link #removeSymbolSpecial(Symbol)} or {@link Symbol#delete()}.
//	 * Deprecated in version 7.4, will be removed a few versions later.
//	 */
//	@Deprecated
//	public boolean removeSymbol(Symbol sym);

	/**
	 * Get the symbol for the given symbol ID.
	 * @param symbolID the id of the symbol to be retrieved.
	 * @return null if there is no symbol with the given ID.
	 */
	public Symbol getSymbol(long symbolID);

	/**
	 * Get the symbol with the given name, address, and namespace.
	 * <P>
	 * Note that for a symbol to be uniquely specified, all these parameters are required. Any method
	 * that queries for symbols using just one or two of these parameters will return a list of symbols.
	 * This method will not return a default thunk (i.e., thunk function symbol with default source type)
	 * since it mirrors the name and parent namespace of the function it thunks.
	 * </P>
	 * @param name the name of the symbol to retrieve
	 * @param addr the address of the symbol to retrieve
	 * @param namespace the namespace of the symbol to retrieve. May be null which indicates global namespace.
	 * @return the symbol which matches the specified crieria or null if not found
	 * @see #getGlobalSymbol(String, Address) for a convenience method if the namespace is the global namespace.
	 */
	public Symbol getSymbol(String name, Address addr, Namespace namespace);

	/**
	 * Get the global symbol with the given name and address.  Note that this results in a single
	 * Symbol because of an additional restriction that allows only one symbol with a given name
	 * at the same address and namespace (in this case the global namespace).
	 *
	 * <P>This is just a convenience method for {@link #getSymbol(String, Address, Namespace)} where
	 * the namespace is the global namespace.</P>
	 * 
	 * <p>NOTE: This method will not return a default thunk (i.e., thunk function symbol with default source type)
	 * since it mirrors the name and parent namespace of the function it thunks.</p>
	 *
	 * @param name the name of the symbol to retrieve
	 * @param addr the address of the symbol to retrieve
	 * @return the symbol which matches the specified crieria in the global namespace or null if not found
	 * @see #getSymbol(String, Address, Namespace)
	 */
	public Symbol getGlobalSymbol(String name, Address addr);

	/**
	 * Returns the first symbol with the given name found in the given namespace. Ghidra now
	 * allows multiple symbols with the same name in the same namespace, so using this method
	 * is likely to produce unintended results. Use {@link #getSymbols(String, Namespace)} instead.
	 * 
	 * <p>NOTE: This method will not return a default thunk (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param name the name of the symbol to retreive
	 * @param namespace the namespace of the symbol to retrieve (null assumes global namespace)
	 * @return the first symbol which satisifies specified criteria or null if not found
	 * @deprecated This method is no longer useful as Ghidra allows duplicate symbol names in
	 * the same namespace. Use {@link #getSymbols(String, Namespace)} instead.
	 * Deprecated in version 7.5, will be removed a few versions later.
	 */
	@Deprecated
	public Symbol getSymbol(String name, Namespace namespace);

	/**
	 * Returns the first global symbol that it finds with the given name.  Now that Ghidra
	 * allows duplicate symbol names, this method is practically useless.
	 * 
	 * <p>NOTE: This method will not return a default thunk (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param name the name of the symbol to be retrieved.
	 * @return first symbol found with specified name or null if no global symbol has that name
	 * @deprecated Use {@link #getGlobalSymbols(String)} instead.  Ghidra now allows
	 * multiple symbols in any namespace to have the same name.  Deprecated in Ghidra 7.5
	 * Deprecated in version 7.5, will be removed a few versions later.
	 */
	@Deprecated
	public Symbol getSymbol(String name);

	/**
	 * Returns a list of all global symbols with the given name.
	 * 
	 * <p>NOTE: This method will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param name the name of the symbols to retrieve.
	 * @return a list of all global symbols with the given name.
	 */
	public List<Symbol> getGlobalSymbols(String name);

	/**
	 * Returns all the label or function symbols that have the given name in the given namespace.
	 * 
	 * <p>NOTE: This method will not return a default thunk (i.e., thunk function symbol with default source type)
	 * since it mirrors the name and parent namespace of the function it thunks.</p>
	 * 
	 * @param name the name of the symbols to search for.
	 * @param namespace the namespace to search.  If null, then the global namespace is assumed.
	 * @return a list of all the label or function symbols with the given name in the given namespace.
	 */
	public List<Symbol> getLabelOrFunctionSymbols(String name, Namespace namespace);

	/**
	 * Returns a generic namespace symbol with the given name in the given namespace.
	 * @param name the name of the namespace symbol to retrieve.
	 * @param namespace the namespace containing the symbol to retrieve.
	 * @return a generic namespace symbol with the given name in the given namespace.
	 */
	public Symbol getNamespaceSymbol(String name, Namespace namespace);

	/**
	 * Returns the library symbol with the given name.
	 * @param name the name of the library symbol to retrieve.
	 * @return  the library symbol with the given name.
	 */
	public Symbol getLibrarySymbol(String name);

	/**
	 * Returns the class symbol with the given name in the given namespace.
	 * @param name the name of the class.
	 * @param namespace the namespace to search for the class.
	 * @return the class symbol with the given name in the given namespace.
	 */
	public Symbol getClassSymbol(String name, Namespace namespace);

	/**
	 * Returns the parameter symbol with the given name in the given namespace.
	 * @param name the name of the parameter.
	 * @param namespace the namespace (function) to search for the class.
	 * @return the parameter symbol with the given name in the given namespace.
	 */
	public Symbol getParameterSymbol(String name, Namespace namespace);

	/**
	 * Returns the local variable symbol with the given name in the given namespace.
	 * @param name the name of the local variable.
	 * @param namespace the namespace (function) to search for the class.
	 * @return the local variable symbol with the given name in the given namespace.
	 */
	public Symbol getLocalVariableSymbol(String name, Namespace namespace);

	/**
	 * Returns a list of all symbols with the given name in the given namespace.
	 * 
	 * <p>NOTE: The resulting iterator will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param name the name of the symbols to retrieve.
	 * @param namespace the namespace to search for symbols.
	 * @return all symbols which satisfy specified criteria
	 */
	public List<Symbol> getSymbols(String name, Namespace namespace);

	/**
	 * Returns a symbol that is either a parameter or local variable.  There can be only
	 * one because these symbol types have a unique name requirement.
	 * @param name the naem of the variable.
	 * @param function the function to search.
	 * @return a parameter or local variable symbol with the given name.
	 */
	public Symbol getVariableSymbol(String name, Function function);

	/**
	 * Returns the namespace with the given name in the given parent namespace.  The namespace
	 * returned can be either a generic namespace or a class or library.  It does not include
	 * functions.
	 * @param name the name of the namespace to be retrieved.
	 * @param namespace the parent namespace of the namespace to be retrieved.
	 * @return the namespace with the given name in the given parent namespace.
	 */
	public Namespace getNamespace(String name, Namespace namespace);

	/**
	 * Returns all the symbols with the given name.
	 * 
	 * <p>NOTE: The resulting iterator will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param name the name of symbols to search for.
	 *
	 * @return array of symbols with the given name
	 */
	public SymbolIterator getSymbols(String name);

	/**
	 * Returns an iterator over all symbols, including Dynamic symbols if
	 * includeDynamicSymbols is true.
	 * @param includeDynamicSymbols if true, the iterator will include dynamicSymbols
	 * @return symbol iterator
	 */
	public SymbolIterator getAllSymbols(boolean includeDynamicSymbols);

	/**
	 * Returns the symbol that this reference is associated with.
	 * @param ref the reference to find the associated symbol for.
	 * @return referenced symbol
	 */
	public Symbol getSymbol(Reference ref);

	/**
	 * Returns the primary symbol at the specified
	 * address.  This method will always return null if the address specified
	 * is neither a Memory address nor an External address.
	 * @param addr the address at which to retrieve the primary symbol
	 *
	 * @return symbol, or null if no symbol at that address
	 */
	public Symbol getPrimarySymbol(Address addr);

	/**
	 * Returns all the symbols at the given address.  When addr is a memory address
	 * the primary symbol will be returned in array slot 0.
	 * WARNING! Use of this method with a Variable address is highly discouraged since
	 * a single Variable address could be used multiple times by many functions.
	 * @param addr the address at which to retrieve all symbols.
	 * @return a zero-length array when no symbols are defined at address.
	 */
	public Symbol[] getSymbols(Address addr);

	/**
	 * Returns an array of all user defined symbols at the given address
	 * @param addr the address at which to retrieve all user defined symbols.
	 * @return all symbols at specified address
	 */
	public Symbol[] getUserSymbols(Address addr);

	/**
	 * Returns an iterator over all the symbols in the given namespace
	 * 
	 * <p>NOTE: The resulting iterator will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param namespace the namespace to search for symbols.
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbols(Namespace namespace);

	/**
	 * Returns an iterator over all the symbols in the given namespace
	 * 
	 * <p>NOTE: This method will not return a default thunk (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param namespaceID the namespace ID to search for symbols.
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbols(long namespaceID);

	/**
	 * Return true if there exists a symbol at the given address.
	 * @param addr address to check for an existing symbol
	 * @return true if any symbol exists
	 */
	public boolean hasSymbol(Address addr);

	/**
	 * Get the unique symbol ID for a dynamic symbol associated with the speified addr.
	 * The generation of this symbol ID does not reflect the presence of a dyanmic symbol
	 * at the specified addr.  This symbol ID should not be permanently stored since the encoding
	 * may change between software releases.
	 * @param addr dynamic symbol address
	 * @return unique symbol ID
	 */
	public long getDynamicSymbolID(Address addr);

	/**
	 * Returns a an iterator over all symbols that match the given search string.
	 * 
	 * <p>NOTE: The iterator is in the forward direction only and will not return default thunk functions.
	 * The resulting iterator will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param searchStr the string to search for (may contain * to match any sequence
	 * or ? to match a single char)
	 * @param caseSensitive flag to determine if the search is case sensitive or not.
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator(String searchStr, boolean caseSensitive);

	/**
	 * Returns all the symbols of the given type within the given address set.
	 * @param set the address set in which to look for symbols of the given type
	 * @param type the SymbolType to look for.
	 * @param forward the direction within the addressSet to search
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbols(AddressSetView set, SymbolType type, boolean forward);

	/**
	 * Returns the total number of symbols in the table.
	 * @return total number of symbols
	 */
	public int getNumSymbols();

	/**
	 * Get iterator over all label symbols. Labels are defined on memory locations.
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator();

	/**
	 * Returns an iterator over all defined symbols in no particular order.
	 * @return symbol iterator
	 */
	public SymbolIterator getDefinedSymbols();

	/**
	 * Returns the external symbol with the given name.
	 * @param name the name of the symbol to be retrieved.
	 * @return symbol, or null if no external symbol has that name
	 */
	public Symbol getExternalSymbol(String name);

	/**
	 * Returns all the external symbols with the given name.
	 * @param name the name of symbols to search for.
	 *
	 * @return array of external symbols with the given name
	 */
	public SymbolIterator getExternalSymbols(String name);

	/**
	 * Returns an iterator over all defined external symbols in no particular order.
	 * @return symbol iterator
	 */
	public SymbolIterator getExternalSymbols();

	/**
	 * Returns an iterator over all symbols.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator(boolean forward);

	/**
	 * Get iterator over all symbols starting at
	 * the specified <code>startAddr</code>
	 * @param startAddr the address at which to begin the iteration.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator(Address startAddr, boolean forward);

	/**
	 * Get iterator over all primary symbols.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getPrimarySymbolIterator(boolean forward);

	/**
	 * Get iterator over only primary symbols starting at
	 * the specified <code>startAddr</code>
	 * @param startAddr the address at which to begin the iteration.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getPrimarySymbolIterator(Address startAddr, boolean forward);

	/**
	 * Get an iterator over symbols at addresses in the given addressSet
	 * @param asv the set of address over which to iterate symbols.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getPrimarySymbolIterator(AddressSetView asv, boolean forward);

	/**
	 * Sets the given address to be an external entry point.
	 * @param addr the address to set as an external entry point.
	 */
	public void addExternalEntryPoint(Address addr);

	/**
	 * Removes the given address as an external entry point.
	 * @param addr the address to remove as an external entry point.
	 */
	public void removeExternalEntryPoint(Address addr);

	/**
	 * Returns true if the given address has been set as an external entry point.
	 * @param addr address to test for external entry point.
	 * @return true if specified address has been marked as an entry point, else false
	 */
	public boolean isExternalEntryPoint(Address addr);

	/**
	 * Get forward/back iterator over addresses that are entry points.
	 * @return entry-point address iterator
	 */
	public AddressIterator getExternalEntryPointIterator();

	/**
	 * Get the label history objects for the given address. The history
	 * object records changes made to labels at some address.
	 * @param addr address of the label change
	 * @return array of history objects
	 */
	public LabelHistory[] getLabelHistory(Address addr);

	/**
	 * Get an iterator over all the label history objects.
	 * @return label history iterator
	 */
	public Iterator<LabelHistory> getLabelHistory();

	/**
	 * Return true if there is a history of label changes at the given address.
	 * @param addr the address to check for symbol history.
	 * @return true if label history exists for specified address, else false
	 */
	public boolean hasLabelHistory(Address addr);

	/**
	 * Returns the lowest level Namespace within which the specified address is contained.
	 * @param addr the address for which to finds its enclosing namespace.
	 * @return namespace which contains specified address
	 */
	public Namespace getNamespace(Address addr);

	/**
	 * Returns all Class Namespaces defined within the program.
	 * @return iterator of {@link GhidraClass}
	 */
	public Iterator<GhidraClass> getClassNamespaces();

	/**
	 * Create a class namespace in the given parent namespace.
	 * @param parent parent namespace
	 * @param name name of the namespace
	 * @param source the source of this class namespace's symbol
	 * @return new class namespace
	 * @throws DuplicateNameException thrown if another non function or label symbol 
	 * exists with the given name
	 * @throws InvalidInputException throw if the name has invalid characters or is null
	 * @throws IllegalArgumentException if you try to set the source to 'Symbol.DEFAULT'.
	 */
	public GhidraClass createClass(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Returns an iterator over all symbols that have the given symbol as its parent.
	 * 
	 * <p>NOTE: The resulting iterator will not return default thunks (i.e., 
	 * thunk function symbol with default source type).</p>
	 * 
	 * @param parentSymbol the parent symbol
	 * @return symbol iterator
	 */
	public SymbolIterator getChildren(Symbol parentSymbol);

	/**
	 * Creates a Library namespace with the given name.
	 * @param name the name of the new Library namespace
	 * @param source the source of this external library's symbol
	 * @return the new Library namespace.
	 * @throws InvalidInputException if the name is invalid.
	 * @throws IllegalArgumentException if you try to set the source to 'Symbol.DEFAULT'.
	 * @throws DuplicateNameException thrown if another non function or label 
	 * symbol exists with the given name
	 */
	public Library createExternalLibrary(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Creates a new namespace.
	 * @param parent the parent namespace for the new namespace
	 * @param name the name of the new namespace
	 * @param source the source of this namespace's symbol
	 * @return the new Namespace object.
	 * @throws DuplicateNameException thrown if another non function or label symbol 
	 * exists with the given name
	 * @throws InvalidInputException if the name is invalid.
	 * @throws IllegalArgumentException if you try to set the source to 'Symbol.DEFAULT'.
	 */
	public Namespace createNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Converts the given namespace to a class namespace
	 * 
	 * @param namespace the namespace to convert
	 * @return the new class
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 * @throws ConcurrentModificationException if the given parent namespace has been deleted
	 */
	public GhidraClass convertNamespaceToClass(Namespace namespace);

	/**
	 * Gets an existing namespace with the given name in the given parent.  If no namespace exists,
	 * then one will be created.
	 *  
	 * @param parent the parent namespace
	 * @param name the namespace name
	 * @param source the source type for the namespace if one is created
	 * @return the namespace
	 * @throws DuplicateNameException thrown if another non function or label symbol exists with 
	 *         the given name
	 * @throws InvalidInputException if the name is invalid
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 * @throws ConcurrentModificationException if the given parent namespace has been deleted
	 */
	public Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;
}
