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
package ghidra.app.cmd.function;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Apply all function signature data types in a data type manager to
 * any user defined label that has the same name as the function
 * signature.
 */
public class ApplyFunctionDataTypesCmd extends BackgroundCommand {
	private Program program;
	private BookmarkManager bookmarkMgr;
	private List<DataTypeManager> managers;
	private AddressSetView addresses;
	private SourceType source;
	private boolean alwaysReplace;
	private boolean createBookmarksEnabled;
	private Map<String, FunctionDefinition> functionNameMap = new HashMap<>();

	/**
	 * Constructs a new command to apply all function signature data types
	 * in the given data type manager.
	 * 
	 * @param managers list of data type managers containing the function signature data types
	 * @param set set of addresses containing labels to match against function names.
	 * 			  The addresses must not already be included in the body of any existing function.
	 *  		  If null, all symbols will be processed
	 * @param source the source of this command.
	 * @param alwaysReplace true to always replace the existing function signature with the
	 * 						function signature data type.
	 * @param createBookmarksEnabled true to create a bookmark when a function signature
	 * 								 has been applied.
	 */
	public ApplyFunctionDataTypesCmd(List<DataTypeManager> managers, AddressSetView set,
			SourceType source, boolean alwaysReplace, boolean createBookmarksEnabled) {
		super("Apply Function Data Types", true, false, false);
		this.managers = managers;
		this.addresses = set;
		this.source = source;
		this.alwaysReplace = alwaysReplace;
		this.createBookmarksEnabled = createBookmarksEnabled;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;
		bookmarkMgr = program.getBookmarkManager();

		monitor.setMessage("Applying Function Signatures");

		Map<String, List<Symbol>> symbolMap = createSymMap();

		applyDataTypes(monitor, symbolMap);

		return true;
	}

	private Map<String, List<Symbol>> createSymMap() {

		Map<String, List<Symbol>> symbolMap = new HashMap<>();

		SymbolTable symbolTable = program.getSymbolTable();
		if (addresses == null) {
			getSymbols(symbolMap, symbolTable.getSymbolIterator());
			getSymbols(symbolMap, symbolTable.getExternalSymbols());
		}
		else {
			getSymbols(symbolMap, symbolTable.getSymbols(addresses, SymbolType.FUNCTION, true));
			getSymbols(symbolMap, symbolTable.getSymbols(addresses, SymbolType.LABEL, true));
		}
		return symbolMap;
	}

	private void getSymbols(Map<String, List<Symbol>> symbolMap, SymbolIterator symbols) {

		while (symbols.hasNext()) {
			Symbol sym = symbols.next();
			if (sym.isDynamic()) {
				continue;
			}

			if (sym.isExternal() || addresses == null || addresses.contains(sym.getAddress())) {
				String name = getValidName(sym.getName());
				List<Symbol> list = symbolMap.get(name);
				if (list == null) {
					list = new LinkedList<>();
					symbolMap.put(name, list);
				}

				list.add(sym);
			}
		}
	}

	/**
	 * Strip off the last name of the string
	 * 
	 * @param name the original string
	 * @return the last name in the string
	 */
	private String getValidName(String name) {
		int pos = name.length() - 1;
		while (pos >= 0 && Character.isJavaIdentifierPart(name.charAt(pos))) {
			pos--;
		}
		String val = name.substring(pos + 1, name.length());

		return val;
	}

	/**
	 * Apply all descendants starting at node.
	 */
	private void applyDataTypes(TaskMonitor monitor, Map<String, List<Symbol>> symbolMap) {

		for (DataTypeManager dataTypeManager : managers) {
			Iterator<DataType> iter = dataTypeManager.getAllDataTypes();
			while (iter.hasNext()) {
				if (monitor.isCancelled()) {
					return;
				}

				DataType dt = iter.next();
				if (!(dt instanceof FunctionDefinition)) {
					continue;
				}

				FunctionDefinition fdef = (FunctionDefinition) dt;
				String name = fdef.getName();
				if (functionNameMap.containsKey(name)) {
					FunctionDefinition dupeFdef = functionNameMap.get(name);
					if (!fdef.isEquivalent(dupeFdef)) {
						// set the functionDef to null to mark dupes
						functionNameMap.put(name, null);
					}
				}
				else {
					functionNameMap.put(name, fdef);
				}
			}

		}
		monitor.initialize(functionNameMap.size());
		for (String functionName : functionNameMap.keySet()) {
			FunctionDefinition fdef = functionNameMap.get(functionName);
			checkForSymbol(monitor, functionName, fdef, symbolMap, null);

			// do any thunks too
			checkForSymbol(monitor, functionName, fdef, symbolMap, "thunk");

			monitor.incrementProgress(1);
		}

	}

	private void checkForSymbol(TaskMonitor monitor, String functionName, FunctionDefinition fdef,
			Map<String, List<Symbol>> symbolMap, String prefix) {

		List<Symbol> symbols = lookupSymbol(symbolMap, prefix, functionName);
		if (symbols == null) {
			return;
		}
		for (Symbol symbol : symbols) {
			checkDoApplyFunctionDefinition(monitor, functionName, fdef, symbol);
		}
	}

	private void checkDoApplyFunctionDefinition(TaskMonitor monitor, String functionName,
			FunctionDefinition fdef, Symbol sym) {

		monitor.setMessage("Apply Function Signature '" + functionName + "'");

		// function
		//    maybe change its signature
		Address address = sym.getAddress();

		Function func = program.getFunctionManager().getFunctionAt(address);
		if (func != null) {
			if (func.isThunk() || func.getSignature(true).equals(fdef)) {
				return;
			}

			SourceType mostTrusted = getMostTrustedParameterSource(func);
			if (alwaysReplace || !source.isLowerPriorityThan(mostTrusted)) {
				applyFunction(sym, fdef);
			}
			return;
		}

		// check if already part of a function
		func = program.getFunctionManager().getFunctionContaining(address);
		if (func != null) {
			// overlap, don't apply
			return;
		}

		if (!isValidFunctionStart(monitor, address)) {
			return;
		}

		// no function
		//    maybe apply
		CreateFunctionCmd functionCmd = new CreateFunctionCmd(address);
		Listing listing = program.getListing();
		if (sym.isExternal() || listing.getInstructionAt(address) != null) {
			// instruction or external - create function, change its signature
			functionCmd.applyTo(program);
			applyFunction(sym, fdef);
			return;
		}

		// symbols in uninitialized blocks are pushed into externals by importer
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null && !block.isInitialized()) {
			return;
		}

		if (listing.getUndefinedDataAt(address) != null) {
			// undefined data - check for likely code
			PseudoDisassembler pdis = new PseudoDisassembler(program);
			if (pdis.isValidSubroutine(address)) {
				DisassembleCommand disassembleCmd = new DisassembleCommand(address, null, true);
				disassembleCmd.applyTo(program);
				functionCmd.applyTo(program);
				applyFunction(sym, fdef);
			}
		}
	}

	/**
	 * Check that the symbol looks like it is at the start of a function.
	 * There can be internal symbols that may match a function name.
	 * 
	 * @param monitor if need to cancel
	 * @param address location of the potential symbol
	 * @return true if the symbol is at the start of a function flow
	 */
	boolean isValidFunctionStart(TaskMonitor monitor, Address address) {
		// instruction above falls into this one
		//   could be non-returning function, but we can't tell now
		Instruction instrBefore = getInstructionBefore(address);
		if (instrBefore != null && address.equals(instrBefore.getFallThrough())) {
			return false;
		}
		
		// check if part of a larger code-block
		ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(address);
		for (Reference reference : referencesTo) {
			RefType referenceType = reference.getReferenceType();

			if (referenceType.isCall()) {
				continue;
			}
			// if a function already existed here, then a jump to here would be OK
			//   but that would be handled by another analyzer
			if (referenceType.isJump()) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get the instruction directly before this address, makeing sure it is the
	 * head instruction in a delayslot
	 * 
	 * @param address to get instruction before
	 * @return instruction if found, null otherwise
	 */
	Instruction getInstructionBefore(Address address) {
		Address addrBefore = address.previous();
		Instruction instrBefore = null;

		while (addrBefore != null) {
			instrBefore = program.getListing().getInstructionContaining(addrBefore);
			if (instrBefore == null) {
				break;
			}
			if (!instrBefore.isInDelaySlot()) {
				break;
			}
			addrBefore = instrBefore.getMinAddress().previous();
		}
		return instrBefore;
	}

	private void applyFunction(Symbol sym, FunctionDefinition fdef) {
		if (fdef == null) {
			Msg.info(this, "Multiple function definitions for " + sym.getName() + " at " +
				sym.getAddress() + " found.  No function signature applied.");
			if (createBookmarksEnabled) {
				bookmarkMgr.setBookmark(sym.getAddress(), BookmarkType.ANALYSIS,
					"Multiple Function Signatures",
					"Found multiple function definitions for: " + sym.getName());
			}
			return;
		}

		ApplyFunctionSignatureCmd fsigCmd =
			new ApplyFunctionSignatureCmd(sym.getAddress(), fdef, source);
		fsigCmd.applyTo(program);
	}

	private SourceType getMostTrustedParameterSource(Function func) {
		SourceType highestSource = SourceType.DEFAULT;
		Parameter[] parameters = func.getParameters();
		for (Parameter parameter : parameters) {
			SourceType paramSource = parameter.getSource();
			if (paramSource.isHigherPriorityThan(highestSource)) {
				highestSource = paramSource;
			}
		}
		return highestSource;
	}

	/**
	 * Lookup any program symbol with the same name as the function signature.
	 * Also allow for a single '_' in front of the symbol name.
	 * 
	 * @param symbolMap map of symbol names to all matching symbols
	 * @param prefix  optional prefix on symbol to lookup
	 * @param fdef    function definition
	 * @return symbol definition; null if no symbol is found for the given name
	 */
	private List<Symbol> lookupSymbol(Map<String, List<Symbol>> symbolMap, String prefix,
			String functionName) {

		if (functionName == null || functionName.length() == 0) {
			return null;
		}

		String loolupName = functionName;
		if (prefix != null) {
			loolupName = prefix + functionName;
		}

		List<Symbol> symbols = symbolMap.get(loolupName);
		if (symbols != null) {
			return symbols;
		}

		symbols = symbolMap.get("_" + loolupName);
		return symbols;
	}
}
