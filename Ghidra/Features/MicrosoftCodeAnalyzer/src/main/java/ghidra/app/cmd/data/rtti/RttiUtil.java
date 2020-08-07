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

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;

import java.io.IOException;
import java.util.List;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * RttiUtil provides constants and static methods for processing RTTI information.
 */
public class RttiUtil {

	static final String CONST_PREFIX = "const ";
	public static final String TYPE_INFO_STRING = ".?AVtype_info@@";
	public static final String TYPE_INFO_LABEL = "class_type_info_RTTI_Type_Descriptor";
	private static final String MANGLED_TYPE_INFO_SYMBOL = "??_R0?AVtype_info@@@8";

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
	 * @return the symbol or null.
	 */
	static Symbol createSymbolFromDemangledType(Program program, Address rttiAddress,
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
			return matchingSymbol;
		}
		// Don't create it if a similar symbol already exists at the address of the data.
		Symbol[] symbols = symbolTable.getSymbols(rttiAddress);
		for (Symbol symbol : symbols) {
			String name = symbol.getName();
			if (name.contains(rttiSuffix)) {
				return symbol; // Similar symbol already exists.
			}
		}
		try {
			// Didn't find the symbol, so create it.
			return symbolTable.createLabel(rttiAddress, rttiSuffix, classNamespace,
				SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			Msg.error(RttiUtil.class,
				"Unable to create label for " + rttiSuffix + " at " + rttiAddress + ".", e);
			return null;
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
		MemoryBlock textBlock = memory.getBlock(".text");
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
			if ((textBlock != null) ? !textBlock.equals(memory.getBlock(referencedAddress))
					: false) {
				break; // Not pointing to text section.
			}
			if (!pseudoDisassembler.isValidSubroutine(referencedAddress, true)) {
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
	 * Gets the address of the base type_info structure in the provided program.
	 * The descriptor will only be manually located if {@value TYPE_INFO_STRING} is present.
	 * @param program the program
	 * @return the address of the type_info structure or null if not found
	 */
	public static Address getTypeInfoTypeDescriptorAddress(Program program) {
		SymbolTable table = program.getSymbolTable();
		List<Symbol> symbols = table.getGlobalSymbols(TYPE_INFO_LABEL);
		if (symbols.isEmpty()) {
			symbols = table.getGlobalSymbols(MANGLED_TYPE_INFO_SYMBOL);
		}
		if (!symbols.isEmpty()) {
			for (Symbol symbol : symbols) {
				if (isTypeInfoTypeDescriptorAddress(program, symbol.getAddress())) {
					return symbol.getAddress();
				}
			}
		}
		return locateTypeInfoAddress(program);
	}

	/**
	 * Checks if the provided address is a TypeDescriptor containing the
	 * {@value TYPE_INFO_STRING} component
	 * @param program the program
	 * @param address the descriptor address
	 * @return true if {@value TYPE_INFO_STRING} is present in the descriptor at the address
	 */
	public static boolean isTypeInfoTypeDescriptorAddress(Program program, Address address) {
		MemoryByteProvider provider = new MemoryByteProvider(program.getMemory(), address);
		try {
			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
			String value = reader.readAsciiString(program.getDefaultPointerSize() * 2);
			return TYPE_INFO_STRING.equals(value);
		} catch (IOException e) {
			return false;
		}
	}
	
	private static Address locateTypeInfoAddress(Program program) {
		Memory memory = program.getMemory();
		try {
			List<MemoryBlock> dataBlocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(
				program, program.getMemory(), ".data", TaskMonitor.DUMMY);
			for (MemoryBlock memoryBlock : dataBlocks) {
				Address typeInfoAddress =
					memory.findBytes(memoryBlock.getStart(), memoryBlock.getEnd(),
						TYPE_INFO_STRING.getBytes(), null, true, TaskMonitor.DUMMY);
				if (typeInfoAddress != null) {
					return TypeDescriptorModel.getBaseAddress(program, typeInfoAddress);
				}
			}
		} catch (CancelledException e) {
			// impossible
			throw new AssertException(e);
		}
		return null;
	}

}
