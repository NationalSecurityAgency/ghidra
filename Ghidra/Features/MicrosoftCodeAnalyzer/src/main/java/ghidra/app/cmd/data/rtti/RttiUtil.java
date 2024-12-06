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
package ghidra.app.cmd.data.rtti;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.*;

import java.util.*;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utility.function.TerminatingConsumer;

/**
 * RttiUtil provides constants and static methods for processing RTTI information.
 */
public class RttiUtil {

	private static final String TYPE_INFO_NAMESPACE = "type_info";
	private static final int MIN_MATCHING_VFTABLE_PTRS = 5;
	static final String CONST_PREFIX = "const ";

	public static final String TYPE_INFO_LABEL = "class_type_info_RTTI_Type_Descriptor";
	public static final String TYPE_INFO_STRING = ".?AVtype_info@@";
	private static final String CLASS_PREFIX_CHARS = ".?A";
	private static Map<Program, Address> vftableMap = new WeakHashMap<>();

	private RttiUtil() {
		// utility class; can't create
	}

	/**
	 * Function that will create a symbol based on the <code>rttiSuffix</code>, which is in the 
	 * class or namespace that is indicated by the <code>demangledType</code> string.
	 * 
	 * @param program the program where the symbol is being created
	 * @param rttiAddress Address of the RTTI datatype 
	 * @param typeDescriptorModel the model for the type descriptor structure
	 * @param rttiSuffix suffix name indicating which type of RTTI structure
	 * @return true if a symbol was created, false otherwise
	 */
	static boolean createSymbolFromDemangledType(Program program, Address rttiAddress,
			TypeDescriptorModel typeDescriptorModel, String rttiSuffix) {

		rttiSuffix = SymbolUtilities.replaceInvalidChars(rttiSuffix, true);

		// Get the namespace for this RTTI's type descriptor.
		Namespace classNamespace = typeDescriptorModel.getDescriptorAsNamespace();

		SymbolTable symbolTable = program.getSymbolTable();

		// See if the symbol already exists for the RTTI data
		Symbol matchingSymbol = symbolTable.getSymbol(rttiSuffix, rttiAddress, classNamespace);
		if (matchingSymbol != null) {
			return false;
		}

		// check for similar symbol
		DemangledObject matchingDemangledObject = null;
		SymbolIterator symbols = symbolTable.getSymbolsAsIterator(rttiAddress);
		for (Symbol symbol : symbols) {
			String name = symbol.getName();

			// if mangled get the matching demangled object if there is one and save for after loop
			// in case symbols are not demangled yet
			DemangledObject demangledObject = DemanglerUtil.demangle(name);
			if (demangledObject != null && demangledObject.getName().contains(rttiSuffix)) {
				matchingDemangledObject = demangledObject;
				continue;
			}

			// Similar symbol already exists - more checking/fixing needed
			if (name.contains(rttiSuffix)) {

				// check for differing namespace to correct pdb in rare cases
				Namespace currentNamespace = symbol.getParentNamespace();
				if (!currentNamespace.equals(classNamespace)) {
					Msg.warn(program, "Removed incorrect pdb symbol: " + symbol.getName(true));
					symbol.delete();
					continue;
				}
				// if symbol contains the matching string and ticks, remove the ticks
				if (replaceSymbolWithNoTicks(symbol)) {
					return true;
				}
			}
		}

		// if it gets here then there were no demangled symbols that contained the rttisuffix
		// indicating that the mangled matching symbol has not been demangled yet and needs to be
		// demangled
		if (matchingDemangledObject != null) {

			String name = matchingDemangledObject.getName();
			if (name.contains(rttiSuffix)) {

				try {
					Symbol symbol = symbolTable.createLabel(rttiAddress, name, classNamespace,
						SourceType.IMPORTED);
					// Set the symbol to be primary so that the demangler 
					// won't demangle again
					symbol.setPrimary();
					if (replaceSymbolWithNoTicks(symbol)) {
						return true;
					}

				}
				catch (InvalidInputException e) {
					//fall through and make a symbol using the rttiSuffix string even though
					// it might really be one with extra information
				}

			}
		}
		// if code gets here then no pdb info so have to make the symbol here
		try {
			Symbol symbol = symbolTable.createLabel(rttiAddress, rttiSuffix, classNamespace,
				SourceType.IMPORTED);
			symbol.setPrimary();
			return true;
		}
		catch (InvalidInputException e) {
			Msg.error(RttiUtil.class,
				"Unable to create label for " + rttiSuffix + " at " + rttiAddress + ".", e);
			return false;
		}
	}

	/**
	 * Method to remove all ' and ` from symbol if it starts with `
	 * @param symbol the symbol
	 * @return true if the symbol has been replaced, false otherwise
	 */
	private static boolean replaceSymbolWithNoTicks(Symbol symbol) {

		String name = symbol.getName();
		if (name.startsWith("`")) {
			name = name.replace("'", "").replace("`", "");
			try {
				symbol.setName(name, symbol.getSource());
				return true;
			}
			catch (DuplicateNameException e) {
				return false;
			}
			catch (InvalidInputException e) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Method to promote the given namespace to a class namespace
	 * @param program the given program
	 * @param namespace the given namespace
	 * @return the promoted class namespace
	 */
	public static Namespace promoteToClassNamespace(Program program, Namespace namespace) {

		if (!(namespace instanceof GhidraClass)) {
			try {
				namespace = NamespaceUtils.convertNamespaceToClass(namespace);
			}
			catch (InvalidInputException iie) {
				Msg.error(RttiUtil.class,
					"Unable to convert namespace to class for namespace " + namespace + ".", iie);
			}
		}
		return namespace;
	}

	/**
	 * Determines the number of vf addresses in the vf table that begins at the specified base 
	 * address.
	 * @param program the program whose memory is providing their addresses
	 * @param vfTableBaseAddress the base address in the program for the vf table
	 * @return the number of virtual function addresses in the vf table
	 */
	public static int getVfTableCount(Program program, Address vfTableBaseAddress) {

		Memory memory = program.getMemory();
		ReferenceManager referenceManager = program.getReferenceManager();
		FunctionManager functionManager = program.getFunctionManager();
		MemoryBlock textBlock = memory.getBlock(".text");
		MemoryBlock nepBlock = memory.getBlock(".nep");
		AddressSetView initializedAddresses = memory.getLoadedAndInitializedAddressSet();
		PseudoDisassembler pseudoDisassembler = new PseudoDisassembler(program);

		// Create pointers starting at the address until reaching a 0 pointer.
		// Terminate the possible table at any entry containing a cross reference that 
		// is beyond the first table entry and don't include it.
		int tableSize = 0;
		Address currentVfPointerAddress = vfTableBaseAddress;
		int defaultPointerSize = program.getDefaultPointerSize();
		while (true) {
			Address referencedAddress = getAbsoluteAddress(program, currentVfPointerAddress);
			if (referencedAddress == null) {
				break; // Cannot get a virtual function address.
			}
			if (referencedAddress.getOffset() == 0) {
				break; // Encountered 0 entry.
			}
			if (!initializedAddresses.contains(referencedAddress)) {
				break; // Not pointing to initialized memory.
			}

			// check in .text and .nep if either exists
			if (textBlock != null || nepBlock != null) {
				MemoryBlock refedBlock = memory.getBlock(referencedAddress);
				boolean inTextBlock = ((textBlock != null) && textBlock.equals(refedBlock));
				boolean inNepBlock = ((nepBlock != null) && nepBlock.equals(refedBlock));
				// if not in either labeled .text/.nep block, then bad vftable pointer
				if (!(inTextBlock || inNepBlock)) {
					break; // Not pointing to good section.
				}
			}

			// any non-computed source type references after the first one ends the table
			if (tableSize > 0 &&
				referenceIndicatesEndOfTable(referenceManager, currentVfPointerAddress)) {
				break;
			}

			Function function = functionManager.getFunctionAt(referencedAddress);

			if (function == null &&
				!pseudoDisassembler.isValidSubroutine(referencedAddress, true, false)) {
				break; // Not pointing to possible function.
			}

			tableSize++; // Count this entry in the table.

			// Advance to the next table entry address.
			currentVfPointerAddress = currentVfPointerAddress.add(defaultPointerSize);
		}
		return tableSize;
	}

	/**
	 * Method to determine if there certain types of references to the given address that would
	 * indicate the end of a vftable
	 * @param address the address of a possible pointer in a vftable
	 * @return true if there are references to the given address and any of the references are
	 * types that would indicate the given pointer should not be in the vftable preceding it. In 
	 * general most references would fall into this category such as ones created by user, importer,
	 * disassembler. Returns false if no references or if the only references are ones not 
	 * indicative of the end of a vftable. 
	 */
	private static boolean referenceIndicatesEndOfTable(ReferenceManager referenceManager,
			Address address) {

		boolean hasReferencesTo = referenceManager.hasReferencesTo(address);
		if (!hasReferencesTo) {
			return false;
		}
		ReferenceIterator referenceIter = referenceManager.getReferencesTo(address);
		while (referenceIter.hasNext()) {
			Reference ref = referenceIter.next();

			// if source type is any besides analysis then it is the kind of reference to stop
			// the vftable
			if (ref.getSource() != SourceType.ANALYSIS) {
				return true;
			}
			// if it is analysis source type but reference is data that is not read this indicates
			// it is not the kind of reference that should end a vftable
			// For example something could be getting this address to figure out the address pointed
			// to so that that address can be referenced. 
			if (ref.getReferenceType().isData() && !ref.getReferenceType().isRead()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets the namespace referred to by the type descriptor model if it can determine the 
	 * namespace. Otherwise it returns the empty string.
	 * @param rtti0Model the model for the type descriptor whose namespace is to be returned.
	 * @return the namespace or the empty string.
	 */
	public static String getDescriptorTypeNamespace(TypeDescriptorModel rtti0Model) {
		String descriptorTypeNamespace = rtti0Model.getDescriptorTypeNamespace(); // Can be null.
		if (descriptorTypeNamespace == null) {
			descriptorTypeNamespace = ""; // Couldn't get namespace so leave it off.
		}
		return descriptorTypeNamespace;
	}

	/**
	 * Identify common TypeInfo address through examination of discovered VtTables
	 */
	private static class CommonRTTIMatchCounter implements TerminatingConsumer<Address> {
		int matchingAddrCount = 0;
		int defaultPointerSize = 4;
		boolean terminationRequest = false;
		Address commonVftableAddress = null;
		Program program;

		public CommonRTTIMatchCounter(Program program) {
			this.program = program;
			defaultPointerSize = program.getDefaultPointerSize();
		}

		public Address getinfoVfTable() {
			return commonVftableAddress;
		}

		@Override
		public boolean terminationRequested() {
			return terminationRequest;
		}

		@Override
		public void accept(Address foundAddress) {
			Address mangledClassNameAddress = foundAddress;

			Address pointerToTypeInfoVftable =
				mangledClassNameAddress.subtract(2 * defaultPointerSize);

			Address possibleVftableAddress =
				MSDataTypeUtils.getAbsoluteAddress(program, pointerToTypeInfoVftable);
			if (possibleVftableAddress == null) {
				return; // valid address not found
			}
			if (possibleVftableAddress.getOffset() == 0) {
				return; // don't want zero_address to count
			}
			// if ever we find one that doesn't match, start count over
			if (!possibleVftableAddress.equals(commonVftableAddress)) {
				if (matchingAddrCount > 2) {
					return;  // already have more than one match, assume this one was outlier, ignore
				}
				matchingAddrCount = 0;
			}

			commonVftableAddress = possibleVftableAddress;
			matchingAddrCount++;

			if (matchingAddrCount > MIN_MATCHING_VFTABLE_PTRS) {
				// done finding good addresses have at Minimum matching number
				terminationRequest = true;
				return;
			}
			return;
		}
	}

	/**
	 * Method to figure out the type_info vftable address using pointed to value by all RTTI classes
	 * @param program the current program
	 * @param monitor the TaskMonitor
	 * @return the type_info address or null if it cannot be determined
	 * @throws CancelledException if cancelled
	 */
	public static Address findTypeInfoVftableAddress(Program program, TaskMonitor monitor)
			throws CancelledException {

		// Checked for cached value
		if (vftableMap.containsKey(program)) {
			return vftableMap.get(program);
		}

		// if type info vftable already a symbol, just use the address of the symbol
		Address infoVftableAddress = findTypeInfoVftableLabel(program);
		if (infoVftableAddress == null) {

			// search for mangled class prefix names, and locate the vftable pointer relative to some
			// minimum number that all point to the same location which should be the vftable
			AddressSetView set = program.getMemory().getLoadedAndInitializedAddressSet();
			List<MemoryBlock> dataBlocks =
				ProgramMemoryUtil.getMemoryBlocksStartingWithName(program, set, ".data", monitor);

			CommonRTTIMatchCounter vfTableAddrChecker = new CommonRTTIMatchCounter(program);

			ProgramMemoryUtil.locateString(CLASS_PREFIX_CHARS, vfTableAddrChecker, program,
				dataBlocks, set, monitor);
			infoVftableAddress = vfTableAddrChecker.getinfoVfTable();
		}

		// cache result of search
		vftableMap.put(program, infoVftableAddress);

		return infoVftableAddress;
	}

	/**
	 * find type info vftable by existing type_info::vftable symbol
	 * @param program program to check
	 * @return return vftable addr if symbol exists
	 */
	private static Address findTypeInfoVftableLabel(Program program) {
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace typeinfoNamespace =
			symbolTable.getNamespace(TYPE_INFO_NAMESPACE, program.getGlobalNamespace());
		Symbol vftableSymbol =
			symbolTable.getLocalVariableSymbol("vftable", typeinfoNamespace);
		if (vftableSymbol != null) {
			return vftableSymbol.getAddress();
		}

		vftableSymbol = symbolTable.getLocalVariableSymbol("`vftable'", typeinfoNamespace);
		if (vftableSymbol != null) {
			return vftableSymbol.getAddress();
		}

		vftableSymbol = symbolTable.getLocalVariableSymbol("type_info", typeinfoNamespace);
		if (vftableSymbol != null) {
			return vftableSymbol.getAddress();
		}

		return null;
	}

	/**
	 * Method to create type_info vftable label (and namespace if needed) at the given address
	 * @param program the current program
	 * @param address the given address
	 */
	public static void createTypeInfoVftableSymbol(Program program, Address address) {

		SymbolTable symbolTable = program.getSymbolTable();

		Namespace typeinfoNamespace =
			symbolTable.getNamespace(TYPE_INFO_NAMESPACE, program.getGlobalNamespace());

		if (typeinfoNamespace == null) {
			try {
				typeinfoNamespace = symbolTable.createClass(program.getGlobalNamespace(),
					TYPE_INFO_NAMESPACE, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				Msg.error(RttiUtil.class, "Duplicate type_info class namespace at " +
					program.getName() + " " + address + ". " + e.getMessage());
				return;
			}
			catch (InvalidInputException e) {
				Msg.error(RttiUtil.class, "Invalid input creating type_info class namespace " +
					program.getName() + " " + address + ". " + e.getMessage());
				return;
			}
		}

		// check to see if symbol already exists both non-pdb and pdb versions
		Symbol vftableSymbol =
			symbolTable.getSymbol(TYPE_INFO_NAMESPACE, address, typeinfoNamespace);
		if (vftableSymbol != null) {
			return;
		}

		vftableSymbol = symbolTable.getSymbol("`vftable'", address, typeinfoNamespace);
		if (vftableSymbol != null) {
			return;
		}

		try {
			vftableSymbol =
				symbolTable.createLabel(address, "vftable", typeinfoNamespace, SourceType.IMPORTED);
			if (vftableSymbol == null) {
				Msg.error(RttiUtil.class,
					program.getName() + " Couldn't create type_info vftable symbol. ");
				return;
			}
			// This fixes the double label issue that happens when there is pdb
			vftableSymbol.setPrimary();
		}
		catch (InvalidInputException e) {
			Msg.error(RttiUtil.class,
				program.getName() + " Couldn't create type_info vftable symbol. " + e.getMessage());
			return;
		}

	}

}
