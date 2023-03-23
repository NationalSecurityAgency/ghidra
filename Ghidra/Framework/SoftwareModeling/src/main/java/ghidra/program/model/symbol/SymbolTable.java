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

import ghidra.program.database.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * A SymbolTable manages the Symbols defined in a program.
 * <p>
 * A Symbol is an association between an Address, a String name. In addition, symbols may have one
 * or more References.
 * <p>
 * A Reference is a 4-tuple of a source address, destination address, type, and either a mnemonic or
 * operand index.
 * <p>
 * Any address in a program can have more than one symbol associated to it. At any given time, one
 * and only one symbol will be designated as the primary.
 * <p>
 * A symbol can be either global or local. Local symbols belong to some namespace other than the
 * global namespace.
 * <p>
 * Label and Function symbols do not have to have unique names with a namespace. All other symbols
 * must be unique within a namespace and be unique with all other symbols that must be unique. In
 * other words, you can have several functions named "foo" and several labels named "foo" in the
 * same namespace. But you can't have a class named "foo" and a namespace named "foo". But you can
 * have a class named "foo" and many functions and labels named "foo" all in the same namespace.
 * <p>
 * A symbol can also be designated as dynamic. Which means the name is generated on-the-fly by the
 * system based on its context.
 */
public interface SymbolTable {

	/**
	 * Create a label symbol with the given name in the global namespace and associated to the 
	 * given memory address. (see {@link Address#isMemoryAddress()}).
	 * <p>
	 * The new symbol will be of type {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} if a 
	 * default function symbol currently exists at the address. If a default function symbol exists 
	 * at the specified address the function symbol will be renamed and returned.  Label and function
	 * symbols do not need to be unique across multiple addresses.  However, if a global symbol at 
	 * the specified address already has the specified name it will be returned without changing the 
	 * source type.  If this is the first non-dynamic symbol defined for the address it becomes the 
	 * primary symbol.  
	 * 
	 * @param addr the memory address at which to create a symbol
	 * @param name the name of the symbol
	 * @param source the source of this symbol.  In general, a source of {@link SourceType#DEFAULT} 
	 *             should never be specified using this method.
	 * @return new labe or function symbol
	 * @throws InvalidInputException if name contains white space, is zero length, or is null for
	 *             non-default source
	 * @throws IllegalArgumentException if {@link SourceType#DEFAULT} is improperly specified, or 
	 *             a non-memory address.
	 */
	public Symbol createLabel(Address addr, String name, SourceType source)
			throws InvalidInputException;

	/**
	 * Create a label symbol with the given name and namespace associated to the given memory 
	 * address.  (see {@link Address#isMemoryAddress()}).
	 * <p>
	 * The new symbol will be of type {@link SymbolType#LABEL} or {@link SymbolType#FUNCTION} if a 
	 * default function symbol currently exists at the address. If a default function symbol exists 
	 * at the specified address the function symbol will be renamed and returned.  Label and function
	 * symbols do not need to be unique across multiple addresses or namespaces.  However, if a 
	 * symbol at the specified address already has the specified name and namespace it will be 
	 * returned without changing the source type.  If this is the first non-dynamic symbol defined 
	 * for the address it becomes the primary symbol. 
	 * 
	 * @param addr the address at which to create a symbol
	 * @param name the name of the symbol
	 * @param namespace the parent namespace of the symbol, or null for the global namespace.
	 * @param source the source of this symbol. In general, a source of {@link SourceType#DEFAULT} 
	 *             should never be specified using this method.
	 * @return new label or function symbol
	 * @throws InvalidInputException if name contains white space, is zero length, or is null for
	 *             non-default source. Also thrown if invalid parent namespace is specified.
	 * @throws IllegalArgumentException if {@link SourceType#DEFAULT} is improperly specified, or 
	 *             a non-memory address, or if the given parent namespace is from a different 
	 *             program than that of this symbol table.
	 */
	public Symbol createLabel(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException;

	/**
	 * Removes the specified symbol from the symbol table.
	 * <p>
	 * If removing any <b>non-function</b> symbol, the behavior will be the same as invoking
	 * {@link Symbol#delete()} on the symbol. Use of this method for non-function symbols is
	 * discouraged.
	 * <p>
	 * <b>WARNING!</b> If removing a function symbol, the behavior differs from directly invoking
	 * {@link Symbol#delete()} on the function symbol. When removing a function symbol this method
	 * has the following behavior:
	 * <ul>
	 * <li>If the function is a default symbol (e.g., FUN_12345678) this method has no effect and
	 * will return false.</li>
	 * <li>If no other labels exist at the function entry, the function will be renamed to the
	 * default function name.</li>
	 * <li>If another label does exist at the function entry point, that label will be removed, and
	 * the function will be renamed to that label's name.</li>
	 * </ul>
	 * <p>
	 * Any reference bound to a removed symbol will lose that symbol specific binding.
	 *
	 * @param sym the symbol to be removed.
	 * @return true if a symbol is removed, false if not or in case of failure
	 */
	public boolean removeSymbolSpecial(Symbol sym);

	/**
	 * Get the symbol for the given symbol ID.
	 * 
	 * @param symbolID the id of the symbol to be retrieved
	 * @return null if there is no symbol with the given ID
	 */
	public Symbol getSymbol(long symbolID);

	/**
	 * Get the symbol with the given name, address, and namespace.
	 * <p>
	 * Note that for a symbol to be uniquely specified, all these parameters are required. Any
	 * method that queries for symbols using just one or two of these parameters will return only
	 * the first match.
	 * <p>
	 * <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
	 * default source type) since it mirrors the name and parent namespace of the function it
	 * thunks.
	 * 
	 * @param name the name of the symbol to retrieve
	 * @param addr the address of the symbol to retrieve
	 * @param namespace the namespace of the symbol to retrieve. May be null which indicates the
	 *            global namespace.
	 * @return the symbol which matches the specified criteria or null if not found
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table
	 * @see #getGlobalSymbol(String, Address) for a convenience method if the namespace is the
	 *      global namespace.
	 */
	public Symbol getSymbol(String name, Address addr, Namespace namespace);

	/**
	 * Get the global symbol with the given name and address.
	 * <p>
	 * Note that this results in a single Symbol because of an additional restriction that allows
	 * only one symbol with a given name at the same address and namespace (in this case the global
	 * namespace).
	 * <p>
	 * This is just a convenience method for {@link #getSymbol(String, Address, Namespace)} where
	 * the namespace is the global namespace.
	 * <p>
	 * <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
	 * default source type) since it mirrors the name and parent namespace of the function it
	 * thunks.
	 *
	 * @param name the name of the symbol to retrieve
	 * @param addr the address of the symbol to retrieve
	 * @return the symbol which matches the specified criteria in the global namespace or null if
	 *         not found
	 * @see #getSymbol(String, Address, Namespace)
	 */
	public Symbol getGlobalSymbol(String name, Address addr);

	/**
	 * Get a list of all global symbols with the given name.  Matches against dynamic label symbols 
	 * will be included.  
	 * <p>
	 * <b>NOTE:</b> This method will not return default thunks (i.e., thunk function symbol with
	 * default source type).
	 * 
	 * @param name the name of the symbols to retrieve
	 * @return a list of all global symbols with the given name
	 */
	public List<Symbol> getGlobalSymbols(String name);

	/**
	 * Get all the label or function symbols that have the given name in the given parent namespace.
	 * If the global namespace is specified matches against dynamic label symbols will be included.  
	 * <p>
	 * <b>NOTE:</b> If a function namespace is specified default parameter and local variable names 
	 * will be included.  If an external library or namespace is specified default external 
	 * label/function symbols will be included.
	 * <p>
	 * <b>NOTE:</b> This method will not return a default thunk (i.e., thunk function symbol with
	 * default source type) since it mirrors the name and parent namespace of the function it
	 * thunks.
	 * 
	 * @param name the name of the symbols to search for
	 * @param namespace the namespace to search. If null, then the global namespace is assumed.
	 * @return a list of all the label or function symbols with the given name in the given parent
	 *         namespace
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public List<Symbol> getLabelOrFunctionSymbols(String name, Namespace namespace);

	/**
	 * Get a generic namespace symbol with the given name in the given parent namespace
	 * 
	 * @param name the name of the namespace symbol to retrieve
	 * @param namespace the namespace containing the symbol to retrieve
	 * @return the symbol, or null
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public Symbol getNamespaceSymbol(String name, Namespace namespace);

	/**
	 * Get the library symbol with the given name
	 * 
	 * @param name the name of the library symbol to retrieve
	 * @return the library symbol with the given name
	 */
	public Symbol getLibrarySymbol(String name);

	/**
	 * Get the class symbol with the given name in the given namespace
	 * 
	 * @param name the name of the class
	 * @param namespace the parent namespace to search for the class
	 * @return the class symbol with the given name in the given namespace
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public Symbol getClassSymbol(String name, Namespace namespace);

	/**
	 * Get the parameter symbol with the given name in the given namespace
	 * 
	 * @param name the name of the parameter
	 * @param namespace the namespace (function) to search for the class
	 * @return the parameter symbol with the given name in the given namespace
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public Symbol getParameterSymbol(String name, Namespace namespace);

	/**
	 * Get the local variable symbol with the given name in the given namespace
	 * 
	 * @param name the name of the local variable
	 * @param namespace the parent namespace (function) to search for the local variable
	 * @return the local variable symbol with the given name in the given namespace
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public Symbol getLocalVariableSymbol(String name, Namespace namespace);

	/**
	 * Get a list of all symbols with the given name in the given parent namespace.  If the global
	 * namespace is specified matches against dynamic label symbols will be included.  
	 * <p>
	 * <b>NOTE:</b> If a function namespace is specified default parameter and local variable names 
	 * will be included.  If an external library or namespace is specified default external 
	 * label/function symbols will be included.
	 * <p>
	 * <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
	 * symbol with default source type).
	 * 
	 * @param name the name of the symbols to retrieve
	 * @param namespace the namespace to search for symbols
	 * @return a list of symbols which satisfy specified criteria
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public List<Symbol> getSymbols(String name, Namespace namespace);

	/**
	 * Get a symbol that is either a parameter or local variable.
	 * <p>
	 * There can be only one because these symbol types have a unique name requirement.
	 * 
	 * @param name the name of the variable
	 * @param function the function to search
	 * @return a parameter or local variable symbol with the given name
	 */
	public Symbol getVariableSymbol(String name, Function function);

	/**
	 * Get the namespace with the given name in the given parent namespace.
	 * <p>
	 * The returned namespace can be a generic namespace ({@link SymbolType#NAMESPACE}, 
	 * {@link NamespaceSymbol}), class ({@link SymbolType#CLASS}, {@link ClassSymbol}),or 
	 * library ({@link SymbolType#LIBRARY}, {@link LibrarySymbol}), but not a function.
	 * <p>
	 * There can be only one because these symbol types have a unique name 
	 * requirement within their parent namespace.
	 * 
	 * @param name the name of the namespace to be retrieved
	 * @param namespace the parent namespace of the namespace to be retrieved
	 * @return the namespace with the given name in the given parent namespace
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *         than that of this symbol table
	 */
	public Namespace getNamespace(String name, Namespace namespace);

	/**
	 * Get all the symbols with the given name
	 * <p>
	 * <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
	 * symbol with default source type). It will also not work for default local variables and
	 * parameters.
	 * 
	 * @param name the name of symbols to search for
	 * @return an iterator over symbols with the given name
	 */
	public SymbolIterator getSymbols(String name);

	/**
	 * Get all of the symbols, optionally including dynamic symbols
	 * 
	 * @param includeDynamicSymbols if true, the iterator will include dynamic symbols
	 * @return an iterator over the symbols
	 */
	public SymbolIterator getAllSymbols(boolean includeDynamicSymbols);

	/**
	 * Get the symbol that a given reference associates
	 * 
	 * @param ref the reference for the associated symbol
	 * @return the associated symbol
	 */
	public Symbol getSymbol(Reference ref);

	/**
	 * Get the primary label or function symbol at the given address
	 * <p>
	 * This method will return null if the address specified is neither a memory address nor an
	 * external address.
	 * 
	 * @param addr the address of the symbol
	 * @return the symbol, or null if no symbol is at the address
	 */
	public Symbol getPrimarySymbol(Address addr);

	/**
	 * Get all the symbols at the given address.  This method will include a dynamic memory symbol
	 * if one exists at the specified address.
	 * <p>
	 * For a memory address the primary symbol will be returned at array index 0. <b>WARNING!</b>
	 * Use of this method with non-memory addresses is discouraged.  Example: Variable
	 * address could be used multiple times by many functions. 
	 * <p>
	 * <b>NOTE:</b> unless all the symbols are needed at once, and a dynamic symbol can be ignored,
	 * consider using {@link #getSymbolsAsIterator(Address)} instead.
	 * 
	 * @param addr the address of the symbols
	 * @return an array, possibly empty, of the symbols at the given address
	 * @see #getSymbolsAsIterator(Address)
	 */
	public Symbol[] getSymbols(Address addr);

	/**
	 * Get an iterator over the symbols at the given address.  Any dynamic symbol at the address
	 * will be excluded.
	 * <p>
	 * Use this instead of {@link #getSymbols(Address)} when you do not need to get all symbols, but
	 * rather are searching for a particular symbol. This method prevents all symbols at the given
	 * address from being loaded up front.
	 * 
	 * @param addr the address of the symbols
	 * @return an iterator over the symbols at the given address
	 * @see #getSymbols(Address)
	 */
	public SymbolIterator getSymbolsAsIterator(Address addr);

	/**
	 * Get an array of defined symbols at the given address (i.e., those with database record).  
	 * Any dynamic memory symbol at the address will be excluded. 
	 * <p>
	 * <b>WARNING!</b>
	 * Use of this method with non-memory addresses is discouraged.  Example: Variable
	 * address could be used multiple times by many functions. 
	 * <p>
	 * <b>NOTE:</b> unless all the symbols are needed at once, consider using 
	 * {@link #getSymbolsAsIterator(Address)} instead. 
	 * 
	 * @param addr the address of the symbols
	 * @return an array, possibly empty, of the symbols
	 */
	public Symbol[] getUserSymbols(Address addr);

	/**
	 * Get an iterator over all the symbols in the given namespace
	 * <p>
	 * <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
	 * symbol with default source type).
	 * 
	 * @param namespace the namespace to search for symbols
	 * @return an iterator over the symbols
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table
	 */
	public SymbolIterator getSymbols(Namespace namespace);

	/**
	 * Get an iterator over all the symbols in the given namespace
	 * <p>
	 * <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
	 * symbol with default source type).
	 * 
	 * @param namespaceID the namespace ID to search for symbols.
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbols(long namespaceID);

	/**
	 * Check if there exists any symbol at the given address
	 * 
	 * @param addr address to check for an existing symbol
	 * @return true if any symbol exists
	 */
	public boolean hasSymbol(Address addr);

	/**
	 * Get the unique symbol ID for a dynamic symbol at the specified address
	 * <p>
	 * Having a dynamic symbol ID does not imply that a dynamic symbol actually exists. Rather, this
	 * just gives the ID that a dynamic symbol at that address would have, should it ever exist.
	 * <p>
	 * <b>NOTE:</b> This symbol ID should not be permanently stored since the encoding may change
	 * between software releases.
	 * 
	 * @param addr the dynamic symbol memory address
	 * @return unique symbol ID
	 * @throws IllegalArgumentException if a non-memory address is specified
	 */
	public long getDynamicSymbolID(Address addr);

	/**
	 * Get an iterator over all symbols that match the given query
	 * <p>
	 * <b>NOTE:</b> The iterator is in the forward direction only and will not return default thunks
	 * (i.e., thunk function symbol with default source type).
	 * 
	 * @param searchStr the query, which may contain * to match any sequence or ? to match a single
	 *            char
	 * @param caseSensitive flag to specify whether the search is case sensitive
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator(String searchStr, boolean caseSensitive);

	/**
	 * Get all the symbols of the given type within the given address set.
	 * <p>
	 * <b>NOTE:</b> All external symbols will be omiitted unless the full 
	 * {@link AddressSpace#EXTERNAL_SPACE} range is included within the specified address set
	 * or a null addressSet is specified.  All global dynamic label symbols will be omitted.
	 * 
	 * @param addressSet the address set containing the symbols.  A null value may be specified
	 * to include all memory and external primary symbols.
	 * @param type the type of the symbols
	 * @param forward the direction of the iterator, by address
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbols(AddressSetView addressSet, SymbolType type, boolean forward);

	/**
	 * Scan symbols lexicographically by name
	 * <p>
	 * If a symbol with the given start name does not exist, the iterator will start at the first
	 * symbol following it. This includes only symbols whose addresses are in memory. In particular,
	 * it excludes external symbols and dynamic symbols, i.e., those generated as a reference
	 * destination.
	 * 
	 * @param startName the starting point
	 * @return an iterator over the symbols in lexicographical order
	 */
	public SymbolIterator scanSymbolsByName(String startName);

	/**
	 * Get the total number of symbols in the table
	 * 
	 * @return total number of symbols
	 */
	public int getNumSymbols();

	/**
	 * Get all label symbols
	 * <p>
	 * Labels are defined on memory locations.
	 * 
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator();

	/**
	 * Get all defined symbols in no particular order.  All global dynamic memory labels will be 
	 * excluded.
	 * 
	 * @return symbol iterator
	 */
	public SymbolIterator getDefinedSymbols();

	/**
	 * Get the external symbol with the given name.  The first occurrence of the named symbol found
	 * within any external namespace will be returned.  If all matching symbols need to be
	 * considered the {@link #getExternalSymbols(String)} should be used.
	 * 
	 * @param name the name of the symbol
	 * @return the symbol, or null if no external symbol has that name
	 */
	public Symbol getExternalSymbol(String name);

	/**
	 * Get all the external symbols with the given name
	 * 
	 * @param name the name of symbols
	 * @return an iterator over the symbols
	 */
	public SymbolIterator getExternalSymbols(String name);

	/**
	 * Get all defined external symbols in no particular order
	 * 
	 * @return symbol iterator
	 */
	public SymbolIterator getExternalSymbols();

	/**
	 * Get all the symbols defined with program memory.
	 * <p>
	 * <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
	 * {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
	 * be omitted.
	 * 
	 * @param forward the direction of the iterator, by address
	 * @return symbol iterator
	 */
	public SymbolIterator getSymbolIterator(boolean forward);

	/**
	 * Get all the symbols starting at the specified memory address.
	 * <p>
	 * <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
	 * {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
	 * be omitted.
	 * 
	 * @param startAddr the starting address
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 * @throws IllegalArgumentException if startAddr is not a memory address
	 */
	public SymbolIterator getSymbolIterator(Address startAddr, boolean forward);

	/**
	 * Get all primary label and function symbols defined within program memory address.
	 * Iteration may span multiple memory spaces. 
	 * <p>
	 * <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
	 * {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
	 * be omitted.
	 * 
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getPrimarySymbolIterator(boolean forward);

	/**
	 * Get all primary label and function symbols starting at the specified memory address through 
	 * to the program's maximum memory address.  Iteration may span multiple memory spaces. 
	 * <p>
	 * <b>NOTE:</b> The returned symbols will not include any external symbols defined within the 
	 * {@link AddressSpace#EXTERNAL_SPACE}.  In addition, all global dynamic label symbols will 
	 * be omitted.
	 * 
	 * @param startAddr the starting memory address
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 * @throws IllegalArgumentException if a non-memory address is specified
	 */
	public SymbolIterator getPrimarySymbolIterator(Address startAddr, boolean forward);

	/**
	 * Get primary label and function symbols within the given address set.  
	 * <p>
	 * <b>NOTE:</b> All external symbols will be omitted unless the full 
	 * {@link AddressSpace#EXTERNAL_SPACE} range is included within the specified address set
	 * or a null addressSet is specified.  All global dynamic label symbols will be omitted.
	 * 
	 * @param addressSet the set of address containing the symbols.  A null value may be specified
	 * to include all memory and external primary symbols.
	 * @param forward true means the iterator is in the forward direction
	 * @return symbol iterator
	 */
	public SymbolIterator getPrimarySymbolIterator(AddressSetView addressSet, boolean forward);

	/**
	 * Add a memory address to the external entry points.
	 * 
	 * @param addr the memory address to add
	 * @throws IllegalArgumentException if a non-memory is specified
	 */
	public void addExternalEntryPoint(Address addr);

	/**
	 * Remove an address from the external entry points
	 * 
	 * @param addr the address to remove
	 */
	public void removeExternalEntryPoint(Address addr);

	/**
	 * Check if the given address is an external entry point
	 * 
	 * @param addr address to check
	 * @return true if specified address has been marked as an entry point, otherwise false
	 */
	public boolean isExternalEntryPoint(Address addr);

	/**
	 * Get the external entry points (addresses)
	 * 
	 * @return entry-point address iterator
	 */
	public AddressIterator getExternalEntryPointIterator();

	/**
	 * Get the label history for the given address
	 * <p>
	 * Each entry records a change made to the labels at the given address
	 * 
	 * @param addr address of the label change
	 * @return array of history objects
	 */
	public LabelHistory[] getLabelHistory(Address addr);

	/**
	 * Get the complete label history of the program
	 * 
	 * @return an iterator over history entries
	 */
	public Iterator<LabelHistory> getLabelHistory();

	/**
	 * Check if there is a history of label changes at the given address
	 * 
	 * @param addr the address to check
	 * @return true if a label history exists for specified address, otherwise false
	 */
	public boolean hasLabelHistory(Address addr);

	/**
	 * Get the deepest namespace containing the given address
	 * 
	 * @param addr the address contained in the namespace
	 * @return the deepest namespace which contains the address
	 */
	public Namespace getNamespace(Address addr);

	/**
	 * Get all class namespaces defined within the program, in no particular order
	 * 
	 * @return an iterator over the classes
	 */
	public Iterator<GhidraClass> getClassNamespaces();

	/**
	 * Create a class namespace in the given parent namespace
	 * 
	 * @param parent the parent namespace, or null for the global namespace
	 * @param name the name of the namespace
	 * @param source the source of this class namespace's symbol
	 * @return the new class namespace
	 * @throws DuplicateNameException thrown if another non function or label symbol exists with the
	 *             given name
	 * @throws InvalidInputException throw if the name has invalid characters or is null
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table or if source is {@link SourceType#DEFAULT}
	 */
	public GhidraClass createClass(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Get all symbols that have the given parent symbol
	 * <p>
	 * <b>NOTE:</b> The resulting iterator will not return default thunks (i.e., thunk function
	 * symbol with default source type) or global dynamic label symbols.
	 * 
	 * @param parentSymbol the parent symbol
	 * @return symbol iterator
	 */
	public SymbolIterator getChildren(Symbol parentSymbol);

	/**
	 * Create a library namespace with the given name
	 * 
	 * @param name the name of the new library namespace
	 * @param source the source of this external library's symbol
	 * @return the new library namespace
	 * @throws InvalidInputException if the name is invalid
	 * @throws IllegalArgumentException if you try to set the source to {@link SourceType#DEFAULT}
	 * @throws DuplicateNameException thrown if another non function or label symbol exists with the
	 *             given name
	 */
	public Library createExternalLibrary(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Create a new namespace
	 * 
	 * @param parent the parent of the new namespace, or null for the global namespace
	 * @param name the name of the new namespace
	 * @param source the source of this namespace's symbol
	 * @return the new namespace
	 * @throws DuplicateNameException if another non function or label symbol exists with the given
	 *             name
	 * @throws InvalidInputException if the name is invalid
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table or if source is {@link SourceType#DEFAULT}
	 */
	public Namespace createNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;

	/**
	 * Convert the given namespace to a class namespace
	 * 
	 * @param namespace the namespace to convert
	 * @return the new class
	 * @throws ConcurrentModificationException if the given parent namespace has been deleted
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table or the namespace not allowed (e.g., global or
	 *             library namespace).
	 */
	public GhidraClass convertNamespaceToClass(Namespace namespace);

	/**
	 * Get or create the namespace with the given name in the given parent
	 * <p>
	 * If the namespace does not already exists, then it will be created.
	 * 
	 * @param parent the parent namespace
	 * @param name the namespace name
	 * @param source the source type for the namespace if it is created
	 * @return the namespace
	 * @throws DuplicateNameException if another non function or label symbol exists with the given
	 *             name
	 * @throws InvalidInputException if the name is invalid
	 * @throws IllegalArgumentException if the given parent namespace is from a different program
	 *             than that of this symbol table
	 * @throws ConcurrentModificationException if the given parent namespace has been deleted
	 */
	public Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException;
}
