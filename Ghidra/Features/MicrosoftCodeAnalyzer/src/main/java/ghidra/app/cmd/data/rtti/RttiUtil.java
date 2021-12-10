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

		// Get or create the namespace for this RTTI's type descriptor.
		Namespace classNamespace = typeDescriptorModel.getDescriptorAsNamespace();

		// If the RTTI's type descriptor is for a class or struct then promote its 
		// namespace to a class.
		// <br>Note: For now this assumes all classes and structs with RTTI data must
		// actually be classes. In the future this might need additional checking before
		// promoting some "struct" ref types to being a class, if we can better determine
		// whether or not they are actually classes. 
		String refType = typeDescriptorModel.getRefType(); // Can be null.
		boolean makeClass = "class".equals(refType) || "struct".equals(refType);
		SymbolTable symbolTable = program.getSymbolTable();
		if (makeClass && (classNamespace != null) && !(classNamespace instanceof GhidraClass)) {
			try {
				classNamespace = NamespaceUtils.convertNamespaceToClass(classNamespace);
			}
			catch (InvalidInputException iie) {
				Msg.error(RttiUtil.class,
					"Unable to convert namespace to class for namespace " + classNamespace + ".",
					iie);
			}
		}

		// See if the symbol already exists for the RTTI data.
		Symbol matchingSymbol = symbolTable.getSymbol(rttiSuffix, rttiAddress, classNamespace);
		if (matchingSymbol != null) {
			return false;
		}
		// Don't create it if a similar symbol already exists at the address of the data.
		SymbolIterator symbols = symbolTable.getSymbolsAsIterator(rttiAddress);
		for (Symbol symbol : symbols) {
			String name = symbol.getName();
			if (name.contains(rttiSuffix)) {
				return false; // Similar symbol already exists.
			}
			// assume any imported symbol is better than what we would put down
			// if mangled, it will get demangled later
			SourceType source = symbol.getSource();
			if (source == SourceType.IMPORTED) {
				return false;
			}
		}
		try {
			// Didn't find the symbol, so create it.
			symbolTable.createLabel(rttiAddress, rttiSuffix, classNamespace,
				SourceType.IMPORTED);
			return true;
		}
		catch (InvalidInputException e) {
			Msg.error(RttiUtil.class,
				"Unable to create label for " + rttiSuffix + " at " + rttiAddress + ".", e);
			return false;
		}
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

			// any references after the first one ends the table
			if (tableSize > 0 && referenceManager.hasReferencesTo(currentVfPointerAddress)) {
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
		}
		catch (InvalidInputException e) {
			Msg.error(RttiUtil.class,
				program.getName() + " Couldn't create type_info vftable symbol. " + e.getMessage());
			return;
		}

	}

}
