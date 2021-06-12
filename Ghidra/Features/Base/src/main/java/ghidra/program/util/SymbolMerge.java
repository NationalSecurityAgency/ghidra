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
package ghidra.program.util;

import java.util.*;

import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>SymbolMerge</code> provides functionality for replacing or merging
 * symbols from one program to another.
 */
class SymbolMerge {

	/** Indicates how often to show progress counter changes. */
	private static final int PROGRESS_COUNTER_GRANULARITY = 129;
	private AddressTranslator originToResultTranslator;
	private Program fromProgram;
	private Program toProgram;
	private SymbolTable fromSymbolTable;
	private SymbolTable toSymbolTable;

	/**
	 * Creates a <code>SymbolMerge</code> for replacing or merging symbols from one program
	 * to another program.
	 * @param fromProgram the program to get symbols "from".
	 * @param toProgram the program to merge symbols "to".
	 */
	SymbolMerge(Program fromProgram, Program toProgram) {
		this.originToResultTranslator = new DefaultAddressTranslator(toProgram, fromProgram);
		this.fromProgram = fromProgram;
		this.toProgram = toProgram;
		this.fromSymbolTable = fromProgram.getSymbolTable();
		this.toSymbolTable = toProgram.getSymbolTable();
	}

	SymbolMerge(AddressTranslator originToResultTranslator) {
		this.originToResultTranslator = originToResultTranslator;
		this.fromProgram = originToResultTranslator.getSourceProgram();
		this.toProgram = originToResultTranslator.getDestinationProgram();
		this.fromSymbolTable = fromProgram.getSymbolTable();
		this.toSymbolTable = toProgram.getSymbolTable();
	}

	/**
	 * This method creates a namespace in one program (the "to" program) that is effectively the
	 * same as the namespace from another program (the "from" program.) It will resolve each
	 * parent namespace in this namespace's parent hierarchy until reaching the global namespace
	 * for the program or until there is no parent namespace.
	 * When resolving any namespace the type of namespace will be the same as it was in the "from"
	 * program. However, the name of the namespace will match the original name in the "from"
	 * program or will be the original name with a conflict suffix attached.
	 * <br>If a namespace that is effectively the same can't be found then this method will create
	 * one and the name may match the original or have a conflict name.
	 * <br>If the namespace can't be resolved, an exception is thrown.
	 * <br>Any namespaces that are created with a conflict name will have their symbol IDs mapped
	 * into the <code>conflictSymbolIDMap</code>.
	 *
	 * @param fromNamespace the namespace in the "from" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @return the resolved namespace in the "to" program. Also the <code>conflictSymbolIDMap</code>
	 * will have been modified, if this namespace had to be created with a conflict name.
	 *
	 * @throws DuplicateNameException if the name space can't be resolved due
	 * to a name conflict that can't be dealt with.
	 * @throws InvalidInputException if the name space is not validly named
	 * for the "to" program.
	 */
	Namespace resolveNamespace(Namespace fromNamespace, LongLongHashtable conflictSymbolIDMap)
			throws DuplicateNameException, InvalidInputException {
		Namespace fromGlobalNs = fromProgram.getGlobalNamespace();
		if (fromNamespace == null) {
			return null;
		}
		if (fromNamespace.equals(fromGlobalNs)) {
			return toProgram.getGlobalNamespace();
		}
		Namespace resolvedNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
		if (resolvedNamespace != null) {
			return resolvedNamespace;
		}
		Symbol fromNamespaceSymbol = fromNamespace.getSymbol();

		// Try to resolve the parent namespace and use it to get/create a namespace.
		Namespace fromParentNs = fromNamespace.getParentNamespace();
		Namespace resolvedParentNs = resolveNamespace(fromParentNs, conflictSymbolIDMap);
		String name = fromNamespaceSymbol.getName();
		SymbolType fromNamespaceSymbolType = fromNamespaceSymbol.getSymbolType();
		Address toNamespaceSymbolAddr =
			originToResultTranslator.getAddress(fromNamespaceSymbol.getAddress());

		// For the resolved parent namespace try to get the namespace we want.
		List<Symbol> toNamespaceSymbols = toSymbolTable.getSymbols(name, resolvedParentNs);
		for (Symbol toNamespaceSymbol : toNamespaceSymbols) {
			SymbolType toNamespaceSymbolType = toNamespaceSymbol.getSymbolType();
			if (toNamespaceSymbolType.isNamespace()) {
				if (toNamespaceSymbolType.equals(fromNamespaceSymbolType) &&
					toNamespaceSymbolAddr.equals(toNamespaceSymbol.getAddress())) {
					return (Namespace) toNamespaceSymbol.getObject(); // Found the equivalent namespace so return it.
				}
			}
		}

		// If we can't get the desired namespace from the resolved parent, then create it.
		resolvedNamespace = createNamespace(name, fromNamespaceSymbolType, toNamespaceSymbolAddr,
			resolvedParentNs, fromNamespaceSymbol.getSource());
		if (!resolvedNamespace.getName().equals(name)) {
			conflictSymbolIDMap.put(fromNamespace.getSymbol().getID(),
				resolvedNamespace.getSymbol().getID());
		}
		return resolvedNamespace;
	}

	/**
	 * Get/create a uniquely named namespace. If the namespace's name can't
	 * be created because of a name conflict, it will be given a new conflict name.
	 * @param name the desired name for the namespace
	 * @param symbolType the symbol type for this namespace
	 * @param address the address for this namespace
	 * This address should be derived from the "to" program.
	 * @param toParentNamespace the parent of this namespace that is in the "to" program.
	 * @param source the source of this symbol
	 * @return an equivalent namespace that exists or was created in the "to" program.
	 * @throws DuplicateNameException if the namespace couldn't be created
	 * because of an unresolvable name conflict.
	 * @throws InvalidInputException if the namespace couldn't be created
	 * because the specified name is invalid in the "to" program.
	 */
	private Namespace createNamespace(String name, SymbolType symbolType, Address address,
			Namespace toParentNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException {

		if (symbolType == SymbolType.FUNCTION) { // function names don't have to be unique
			return (Namespace) createSymbol(name, symbolType, address, toParentNamespace, source);
		}

		// Need to create a unique named namespace that is equivalent to original.
		for (int i = 0; i < Integer.MAX_VALUE; i++) {
			String uniqueName = (i == 0) ? name : name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
			Namespace ns = toSymbolTable.getNamespace(uniqueName, toParentNamespace);
			if (ns != null) {
				Symbol s = ns.getSymbol();
				if (!s.getAddress().equals(address) || !s.getSymbolType().equals(symbolType)) {
					continue; // Not the right one, so go to next conflict name.
				}
				// Found the equivalent namespace so return it.
				return ns;
			}
			// Create it, since nothing with this conflict name.
			Symbol uniqueSymbol =
				createSymbol(uniqueName, symbolType, address, toParentNamespace, source);
			if (uniqueSymbol != null) {
				Object obj = uniqueSymbol.getObject();
				if (obj instanceof Namespace) {
					return (Namespace) obj;
				}
			}
			break; // Otherwise throw exception
		}
		throw new DuplicateNameException("Couldn't create namespace '" + name + "' in namespace '" +
			toParentNamespace.getName(true) + "'.");
	}

	/**
	 * Creates a new symbol of the indicated type along with its associated Object in the "to" program.
	 * <br>This method will throw an exception if the symbol can't be created.
	 * <br>Note: It will not create a symbol with a conflict name.
	 * @param name the name for the symbol
	 * @param type the symbol type for this symbol
	 * @param address the address for this symbol
	 * This address should be derived from the "to" program.
	 * @param parentNamespace the parent namespace of this symbol that is in the "to" program
	 * @param source the source of this symbol.
	 * @return a new symbol. Returns null if it can't create a symbol of the indicated type..
	 * @throws DuplicateNameException if the symbol and Object couldn't be created
	 * because of an unresolvable name conflict.
	 * @throws InvalidInputException if the symbol and Object couldn't be created
	 * because of an invalid name.
	 */
	private Symbol createSymbol(String name, SymbolType type, Address address,
			Namespace parentNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Symbol symbol = null;
		if (type == SymbolType.LABEL) {
			if (address.isExternalAddress()) {
// FIXME Should this be passing the Namespace?
				ExternalManagerDB extMgr = (ExternalManagerDB) toProgram.getExternalManager();
				ExternalLocation addExtLocation =
					extMgr.addExtLocation(parentNamespace.getName(), name, address, source);
				return addExtLocation.getSymbol();
			}
			symbol = toSymbolTable.createLabel(address, name, parentNamespace, source);
		}
//		else if (type == SymbolType.EXTERNAL) {
//			ExternalManagerDB extMgr = (ExternalManagerDB) toProgram.getExternalManager();
//			extMgr.addExtLocation(parentNamespace.getName(), name, address, source);
//			symbol = toSymbolTable.getSymbol(name, parentNamespace);
//		}
		else if (type == SymbolType.CLASS) {
			GhidraClass newGhidraClass = toSymbolTable.createClass(parentNamespace, name, source);
			symbol = newGhidraClass.getSymbol();
		}
		else if (type == SymbolType.NAMESPACE) {
			Namespace newNamespace = toSymbolTable.createNameSpace(parentNamespace, name, source);
			symbol = newNamespace.getSymbol();
		}
		else if (type == SymbolType.LIBRARY) {
			ExternalManager fromExtMgr = fromProgram.getExternalManager();
			String path = fromExtMgr.getExternalLibraryPath(name);

			ExternalManagerDB extMgr = (ExternalManagerDB) toProgram.getExternalManager();
			extMgr.setExternalPath(name, path, source == SourceType.USER_DEFINED);
			symbol = toSymbolTable.getLibrarySymbol(name);
		}
		else if (type == SymbolType.FUNCTION) {
			FunctionManager fromFunctionMgr = fromProgram.getFunctionManager();
			AddressSetView body = fromFunctionMgr.getFunctionAt(address).getBody();
			FunctionManager functionMgr = toProgram.getFunctionManager();
			try {
				functionMgr.createFunction(name, parentNamespace, address, body, source);
			}
			catch (OverlappingFunctionException e) {
				throw new InvalidInputException(e.getMessage());
			}
			symbol = toSymbolTable.getSymbol(name, address, parentNamespace);
		}
		return symbol;
	}

	/**
	 * <code>replaceSymbols</code> will replace the symbols at the indicated address
	 * in the destination program with those from the source program. If the same symbol exists
	 * in the source and destination programs, this method will simply allow it to remain in the
	 * destination program. For a symbol to be the same, it must have the same name and the same
	 * parent namespace path. The primary symbol will be get set to the symbol that was primary in
	 * the source program.
	 *
	 * @param address the program address where the symbols are being replaced.
	 * This address should be derived from the "to" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for updating user progress and allowing cancelling.
	 *
	 * @return a map of symbols that were created as conflicts during the replace. These map symbols
	 * in the source program to a symbol with another name due to a duplicate symbol problem.
	 * (key = "from" program's symbol; value = "to" program's symbol)
	 *
	 * @throws CancelledException if the task monitor is cancelled.
	 * @throws DuplicateNameException if the name space can't be resolved due
	 * to a name conflict that can't be dealt with.
	 * @throws InvalidInputException
	 * the indicated address.
	 */
	void replaceSymbols(Address address, LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws CancelledException, DuplicateNameException, InvalidInputException {

		removeUniqueToSymbols(address, monitor);
		replaceFunctionSymbol(address, address, conflictSymbolIDMap, monitor);
		addFromSymbols(address, true, conflictSymbolIDMap, monitor);

		replacePrimary(address, conflictSymbolIDMap);

		// Remove this address as an entry point if its not one in program2.
		if (toSymbolTable.isExternalEntryPoint(address) &&
			!fromSymbolTable.isExternalEntryPoint(address)) {
			toSymbolTable.removeExternalEntryPoint(address);
		}
		else if (fromSymbolTable.isExternalEntryPoint(address) &&
			!toSymbolTable.isExternalEntryPoint(address)) {
			toSymbolTable.addExternalEntryPoint(address);
		}
	}

	/**
	 * <code>removeUniqueToSymbols</code> removes all the symbols in the
	 * destination program at the specified address that don't have the same
	 * symbol in the source program at that address. The FUNCTION symbol will
	 * not be removed at the address even if it is different. Otherwise, the
	 * function would inadvertently get removed.
	 *
	 * @param address the program address where the symbols are being replaced.
	 * This address should be derived from the "to" program.
	 * @param monitor the task monitor for updating user progress and allowing cancelling.
	 *
	 * @throws CancelledException if the task monitor is cancelled.
	 */
	private void removeUniqueToSymbols(Address fromAddress, TaskMonitor monitor)
			throws CancelledException {
		Address toAddress = originToResultTranslator.getAddress(fromAddress);
		Symbol[] toSymbols = toSymbolTable.getUserSymbols(toAddress);
		for (Symbol toSymbol : toSymbols) {
			Symbol fromSymbol = SimpleDiffUtility.getSymbol(toSymbol, fromProgram);
			if (fromSymbol == null) {
				if (toSymbol.getSymbolType() != SymbolType.FUNCTION) {
					toSymbolTable.removeSymbolSpecial(toSymbol);
				}
				continue;
			}
			if (fromSymbol.getSymbolType() == SymbolType.FUNCTION) {
				continue;
			}
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace toNamespace = toSymbol.getParentNamespace();
			Namespace expectedToNamespace = DiffUtility.getNamespace(fromNamespace, toProgram);
			if (toNamespace != expectedToNamespace) {
				toSymbolTable.removeSymbolSpecial(toSymbol);
			}
			monitor.checkCanceled();
		}
	}

	/**
	 * Adds symbols to the "to" program that are not in the "to" program, but are in the
	 * "from" program.
	 * @param fromAddress the program address where the symbols are being added from.
	 * This address should be derived from the "from" program.
	 * @param replace true indicates this method is being called as part of a replace.
	 * false indicates this method is being done as part of a merge.
	 * <br>Note: merge and replace require different behaviors here.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for updating user progress and allowing cancelling.
	 *
	 * @return an array of <code>SymbolTranslators</code> for symbols that ended up with different
	 * pathnames in the destination program than they had in the source program. These map symbols
	 * in the source program to a symbol with another name due to a duplicate symbol problem.
	 *
	 * @throws CancelledException if the task monitor is canceled.
	 * @throws DuplicateNameException if a symbol couldn't be added due
	 * to a name conflict that can't be dealt with.
	 * @throws InvalidInputException if the symbol name being used to create a symbol in the
	 * destination program is not valid.
	 */
	private void addFromSymbols(Address fromAddress, boolean replace,
			LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws CancelledException, InvalidInputException, DuplicateNameException {
		Address toAddress = originToResultTranslator.getAddress(fromAddress);
		Symbol[] fromSymbols = fromSymbolTable.getUserSymbols(fromAddress);
		for (Symbol fromSymbol : fromSymbols) {
			monitor.checkCanceled();
			if (fromSymbol.getSymbolType().equals(SymbolType.FUNCTION)) {
				continue; // handle function symbols separately
			}
			SourceType fromSource = fromSymbol.getSource();
			String fromName = fromSymbol.getName();
			Namespace fromNamespace = fromSymbol.getParentNamespace();
			Namespace desiredToNamespace =
				determineToNamespace(toAddress, fromNamespace, conflictSymbolIDMap);
			Symbol toSymbol = toSymbolTable.getSymbol(fromName, toAddress, desiredToNamespace);
			if (toSymbol == null) {
				toSymbol =
					toSymbolTable.createLabel(toAddress, fromName, desiredToNamespace, fromSource);
			}
			else if (replace && toSymbol.getSource() != fromSource) {
				try {
					toSymbol.setSource(fromSource);
				}
				catch (IllegalArgumentException e) {
					Msg.warn(this, e.getMessage());
				}
			}
			boolean pinned = fromSymbol.isPinned();
			if (replace && toSymbol.isPinned() != pinned) {
				toSymbol.setPinned(pinned);
			}
//			String fromComment = fromSymbol.getSymbolData3();
//			String toComment = toSymbol.getSymbolData3();
//			if (!SystemUtilities.isEqual(fromComment, toComment)) {
//				String newComment;
//				if (replace) {
//					newComment = fromComment;
//				}
//				else {
//					newComment = StringUtilities.mergeStrings(fromComment, toComment);
//				}
//				toSymbol.setSymbolData3(newComment);
//			}
		}
	}

	private Namespace determineToNamespace(Address toAddress, Namespace fromNamespace,
			LongLongHashtable conflictSymbolIDMap) {
		if (fromNamespace.getSymbol().getSymbolType() == SymbolType.FUNCTION) {
			Function toFunction = toProgram.getFunctionManager().getFunctionContaining(toAddress);
			if (toFunction != null) {
				return toFunction;
			}
		}
		else {
			try {
				Namespace newNamespace = resolveNamespace(fromNamespace, conflictSymbolIDMap);
				if (newNamespace != null) {
					return newNamespace;
				}
			}
			catch (InvalidInputException | DuplicateNameException e) {
				// Default to global namespace
			}
		}
		return toProgram.getGlobalNamespace();
	}

	/**
	 * Replaces the function symbol at the indicated entry point in the "to" program with the
	 * function symbol in the "from" program. If there is no function in the "to" program the
	 * symbol becomes a regular "label" symbol.
	 * @param fromEntryPoint the entry point address
	 * This address should be derived from the "from" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 *
	 * @throws InvalidInputException if the function symbol name from the second program isn't valid
	 * @throws DuplicateNameException if a duplicate name is encountered that couldn't be handled
	 * while replacing the function symbol.
	 */
	private void replaceFunctionSymbol(Address fromEntryPoint, Address toEntryPoint,
			LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException {
		// Assumes: The function in the destination program should already be replaced at this point.
		// However, the symbol name and name space have not been replaced.
		FunctionManager fromFunctionMgr = fromProgram.getFunctionManager();
		FunctionManager toFunctionMgr = toProgram.getFunctionManager();
		Function fromFunc = fromFunctionMgr.getFunctionAt(fromEntryPoint);
		Function toFunc = toFunctionMgr.getFunctionAt(toEntryPoint);
		if (fromFunc == null) {
			return;
		}

		Symbol fromSymbol = fromFunc.getSymbol();
		SourceType fromSource = fromSymbol.getSource();
		boolean isFromDefaultThunk = FunctionMerge.isDefaultThunk(fromFunc);
		String fromName = fromSymbol.getName();
		Namespace fromNamespace = // default thunks will lie about their namespace
				isFromDefaultThunk ? fromProgram.getGlobalNamespace() : fromSymbol.getParentNamespace();

		Symbol toSymbol;
		if (toFunc == null) {
			if (fromSource == SourceType.DEFAULT) {
				return;
			}
			Namespace toNamespace = toProgram.getGlobalNamespace();
			toFunc = toFunctionMgr.getFunctionContaining(toEntryPoint);
			if (toFunc != null) {
				toNamespace = toFunc;
			}
			// If replacing a function name, but there isn't a function in the destination,
			// create a regular label with the function name unless its the default name.
			toSymbol = toSymbolTable.createLabel(toEntryPoint, fromName, toNamespace, fromSource);
		}
		else {
			toSymbol = toFunc.getSymbol();

			// Replacing the function name.
			if (toSymbol.equals(fromSymbol)) {
				if (fromSource != SourceType.DEFAULT && toSymbol.getSource() != fromSource) {
					try {
						toSymbol.setSource(fromSource);
					}
					catch (IllegalArgumentException e) {
						Msg.warn(this, e.getMessage());
					}
				}
				boolean pinned = fromSymbol.isPinned();
				if (toSymbol.isPinned() != pinned) {
					toSymbol.setPinned(pinned);
				}
				return; // Symbols aren't different.
			}

			Namespace newToNamespace = resolveNamespace(fromNamespace, conflictSymbolIDMap);
			try {
				toFunc.setParentNamespace(newToNamespace);
			}
			catch (CircularDependencyException | InvalidInputException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}

			String toName = toSymbol.getName();
			if (toSymbol.getSource() != fromSource || !toName.equals(fromName)) {
				toFunc.setName(fromName, fromSource);
			}
		}

		boolean pinned = fromSymbol.isPinned();
		if (toSymbol.isPinned() != pinned) {
			toSymbol.setPinned(pinned);
		}
	}

	/**
	 * Merges the function symbol at the indicated entry point from the "from" program into the
	 * "to" program. The function is merged  as a regular "label" symbol.
	 * @param fromEntryPoint the entry point address
	 * This address should be derived from the "from" program.
	 * @param replacePrimary true indicates that the primary symbol in the "to" program should be
	 * set to the function symbol if there was one in the "from" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 *
	 * @throws InvalidInputException if the function symbol name from the second program isn't valid
	 * @throws DuplicateNameException if a duplicate name is encountered that couldn't be handled
	 * while copying the function symbol.
	 */
	private void mergeFunctionSymbol(Address fromEntryPoint, boolean replacePrimary,
			LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws DuplicateNameException, InvalidInputException {
		// Assumes: The function in the destination program should already be replaced at this point.
		FunctionManager fromFunctionMgr = fromProgram.getFunctionManager();
		FunctionManager toFunctionMgr = toProgram.getFunctionManager();
		Address toEntryPoint = originToResultTranslator.getAddress(fromEntryPoint);
		Function fromFunc = fromFunctionMgr.getFunctionAt(fromEntryPoint);
		Function toFunc = toFunctionMgr.getFunctionAt(toEntryPoint);
		SymbolTable toSymTab = toProgram.getSymbolTable();
		if (fromFunc != null) {
			Symbol fromSymbol = fromFunc.getSymbol();
			String fromName = fromSymbol.getName();
			boolean fromDefault = fromSymbol.getSource() == SourceType.DEFAULT;
			boolean isFromDefaultThunk = FunctionMerge.isDefaultThunk(fromFunc);
			Namespace fromNamespace = // default thunks will lie about their namespace
					isFromDefaultThunk ? fromProgram.getGlobalNamespace() : fromSymbol.getParentNamespace();

			Namespace resolveNamespace = resolveNamespace(fromNamespace, conflictSymbolIDMap);
			if ((toFunc != null) && replacePrimary && !fromDefault) {
				// Save "to" function name and namespace.
				String toName = toFunc.getName();
				SourceType toSource = toFunc.getSymbol().getSource();
				boolean toDefault = toSource == SourceType.DEFAULT;
				Namespace toNamespace = toFunc.getParentNamespace();

				// Merging function name into function as primary.
				replaceFunctionSymbol(fromEntryPoint, toEntryPoint, conflictSymbolIDMap, monitor);
				if (!toDefault && !toName.equals(fromName)) {
					// Merge "to" function name and namespace as label.
					addFunctionAsLabel(toEntryPoint, conflictSymbolIDMap, toSymTab, toSource,
						toName, toNamespace, -1L);
				}
			}
			else if (toFunc != null) {
				if (isFromDefaultThunk && FunctionMerge.isDefaultThunk(toFunc)) {
					return;
				}
				
				if (toFunc.getSymbol().getSource() == SourceType.DEFAULT) {
					// Default "to" function so replace
					replaceFunctionSymbol(fromEntryPoint, toEntryPoint, conflictSymbolIDMap,
						monitor);
				}
				else if (!fromDefault) {
					// No "to" function or not merging primary.
					addFunctionAsLabel(toEntryPoint, conflictSymbolIDMap, toSymTab,
						fromSymbol.getSource(), fromName, resolveNamespace, fromSymbol.getID());
				}
			}
			else if (!isFromDefaultThunk) {
				// No "to" function or not merging primary.
				addFunctionAsLabel(toEntryPoint, conflictSymbolIDMap, toSymTab,
					fromSymbol.getSource(), fromName, resolveNamespace, fromSymbol.getID());
			}
		}
	}

	private void addFunctionAsLabel(Address entryPoint, LongLongHashtable conflictSymbolIDMap,
			SymbolTable toSymTab, SourceType source, String fromName, Namespace toNamespace,
			long oldID) throws InvalidInputException {

		Symbol toSymbol = toSymTab.getSymbol(fromName, entryPoint, toNamespace);
		if (((toSymbol == null) || !toSymbol.getSymbolType().equals(SymbolType.LABEL)) &&
			(source != SourceType.DEFAULT)) {
			if (toSymTab.getSymbol(fromName, entryPoint, toNamespace) == null) {
				toSymbol = toSymbolTable.createLabel(entryPoint, fromName, toNamespace, source);
			}
		}
	}

	/**
	 * <CODE>mergeLabels</CODE> merges all symbols and aliases
	 * in the specified address set from the second program.
	 * It merges them into the merge program.
	 *
	 * @param addrSet the addresses to be merged.
	 * @param filter the current merge filter settings indicating what types
	 * of differences should be merged.
	*
	 * @throws CancelledException if user cancels via the monitor.
	 */
	/**
	 * <CODE>mergeLabels</CODE> either replaces the symbols in the "to" program with those in the
	 * "from" program or merges the symbols from the "from" program into the "to" program at
	 * the indicated addresses.
	 * @param fromAddressSet the addresses where symbols should be replaced or merged.
	 * The addresses in this set should be derived from the "from" program.
	 * @param setting indicates whether to replace or merge the symbols.
	 * @param replacePrimary true indicates that the primary symbol in the "to" program should be
	 * set to the same symbol as was primary in the "from" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	void mergeLabels(AddressSetView fromAddressSet, int setting, boolean replacePrimary,
			boolean replaceFunction, LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge code units.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Merging Labels...");
		if (fromAddressSet.isEmpty()) {
			return;
		}

		// Get the code units in the merge program in this address set.
		CodeUnitIterator fromCui = fromProgram.getListing().getCodeUnits(fromAddressSet, true);
		// Get each address in the address set and get the symbol for it.
		for (long count = 0; fromCui.hasNext() && !monitor.isCancelled(); count++) {
			CodeUnit fromCu = fromCui.next();
			Address fromMin = fromCu.getMinAddress();
			Address fromMax = fromCu.getMaxAddress();
			for (Address fromAddress = fromMin; fromAddress.compareTo(fromMax) <= 0;) {
				Address toAddress = originToResultTranslator.getAddress(fromAddress);
				try {
					if (fromSymbolTable.hasSymbol(fromAddress) ||
						toSymbolTable.hasSymbol(toAddress)) {
						if (setting == ProgramMergeFilter.MERGE) {
							if (count == PROGRESS_COUNTER_GRANULARITY) {
								monitor.setMessage(
									"Merging Labels...   " + fromAddress.toString(true));
								count = 0;
							}
							copySymbols(fromAddress, replacePrimary, replaceFunction,
								conflictSymbolIDMap, monitor);
						}
						else if (setting == ProgramMergeFilter.REPLACE) {
							if (count == PROGRESS_COUNTER_GRANULARITY) {
								monitor.setMessage(
									"Replacing Labels...   " + fromAddress.toString(true));
								count = 0;
							}
							replaceSymbols(fromAddress, conflictSymbolIDMap, monitor);
						}
					}
				}
				catch (DuplicateNameException e1) {
					// TODO Auto-generated catch block
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
				catch (InvalidInputException e1) {
					// TODO Auto-generated catch block
					Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				}
				try {
					fromAddress = fromAddress.addNoWrap(0x1L);
				}
				catch (AddressOverflowException e) {
					break;
				}
			}
		}
	}

	/** replaceSymbol adds the symbol and its aliases from the fromProgram's SymbolTable to
	 *  the toProgram's SymbolTable. If the toSymbolTable already has a symbol (and
	 *  possibly aliases) they are removed and the symbol and aliases from the
	 *  fromProgram's SymbolTable are added.
	 * @param fromAddress the address where the symbols will be copy from/to.
	 * This address should be derived from the "from" program.
	 * @param replacePrimary true indicates that the primary symbol in the "to" program should be
	 * set to the same symbol as was primary in the "from" program.
	 * @param replaceFunction true indicates that the function symbol in the "to" program should be
	 * set to the same function symbol as in the "from" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @return the symbol now at the address in the toSymbolTable.
	 *
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws InvalidInputException if a symbol name from the second program isn't valid
	 * @throws DuplicateNameException if a duplicate name is encountered that couldn't be handled
	 * while copying a symbol.
	 */
	void copySymbols(Address fromAddress, boolean replacePrimary, boolean replaceFunction,
			LongLongHashtable conflictSymbolIDMap, TaskMonitor monitor)
			throws CancelledException, DuplicateNameException, InvalidInputException {

		Address toAddress = originToResultTranslator.getAddress(fromAddress);
		addFromSymbols(fromAddress, false, conflictSymbolIDMap, monitor);
		mergeFunctionSymbol(fromAddress, replacePrimary || replaceFunction, conflictSymbolIDMap,
			monitor);

		if (replacePrimary) {
			replacePrimary(toAddress, conflictSymbolIDMap);
		}

		// Make this address an entry point if its one in program2.
		if (fromSymbolTable.isExternalEntryPoint(fromAddress) &&
			!toSymbolTable.isExternalEntryPoint(toAddress)) {
			toSymbolTable.addExternalEntryPoint(toAddress);
		}
	}

	/**
	 *
	 * @param address
	 * This address should be derived from the "to" program.
	 * @param conflictSymbolIDMap maps the symbol IDs in the "from" program to the symbol IDs
	 * in the "to" program for any symbols (and their associated objects) that were created
	 * with conflict names.
	 * (key = "from" program's symbol ID; value = "to" program's symbol ID)
	 */
	private void replacePrimary(Address address, LongLongHashtable conflictSymbolIDMap) {
		// Set the primary symbol.
		Symbol fromPrimary = fromSymbolTable.getPrimarySymbol(address);
		if (fromPrimary != null) {
			Symbol newToPrimary = null;
			try {
				long newToPrimaryID = conflictSymbolIDMap.get(fromPrimary.getID());
				newToPrimary = toSymbolTable.getSymbol(newToPrimaryID);
			}
			catch (NoValueException e) {
				newToPrimary = SimpleDiffUtility.getSymbol(fromPrimary, toProgram);
			}
			if ((newToPrimary != null) && !newToPrimary.isPrimary()) {
				newToPrimary.setPrimary();
			}
		}
	}

	static void reApplyDuplicateSymbols(Hashtable<Symbol, Symbol> dupSyms) {
		Enumeration<Symbol> keys = dupSyms.keys();
		while (keys.hasMoreElements()) {
			Symbol fromSym = keys.nextElement();
			Symbol toSym = dupSyms.get(fromSym);
			try {
				toSym.setName(fromSym.getName(), fromSym.getSource());
				dupSyms.remove(fromSym);
			}
			catch (DuplicateNameException e) {
				continue; // Leaves it in the hashtable
			}
			catch (InvalidInputException e) {
				continue; // Leaves it in the hashtable
			}
		}
	}

	static String getDuplicateSymbolsInfo(Hashtable<Symbol, Symbol> dupSyms) {
		StringBuffer buf = new StringBuffer();
		Enumeration<Symbol> keys = dupSyms.keys();
		while (keys.hasMoreElements()) {
			Symbol fromSym = keys.nextElement();
			Symbol toSym = dupSyms.get(fromSym);
			String msg = "Symbol '" + fromSym.getName(true) + "' renamed to '" +
				toSym.getName(true) + "' due to name conflict.\n";
			buf.append(msg);
		}
		return buf.toString();
	}
}
