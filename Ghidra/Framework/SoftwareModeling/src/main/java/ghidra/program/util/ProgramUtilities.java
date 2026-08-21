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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * General utility class that provides convenience methods
 * to deal with Program objects. 
 */
public class ProgramUtilities {

	private final static String EXTERNAL_ADDRESS_PREFIX = AddressSpace.EXTERNAL_SPACE.toString();

	private ProgramUtilities() {
	}

	/** The read-only program icon. */
	private static Map<Program, Object> openProgramsWeakMap = new WeakHashMap<Program, Object>();

	public static DataConverter getDataConverter(Program program) {
		if (program.getMemory().isBigEndian()) {
			return BigEndianDataConverter.INSTANCE;
		}
		return LittleEndianDataConverter.INSTANCE;
	}

	/**
	 * Programs will only be stored during testing and are maintained as weak references.
	 * @param program The program that is being tracked (all programs during testing.
	 */
	public static void addTrackedProgram(Program program) {
		if (SystemUtilities.isInTestingMode()) {
			openProgramsWeakMap.put(program, null);
		}
	}

	/**
	 * Returns an iterator for all of the {@link Program} objects in the system, which is all
	 * created programs in any state that have not been garbage collected.  
	 * <p>
	 * <b>Note:</b>The Iterator is backed by an unmodifiable set, so any attempts to modify the
	 * Iterator will throw an {@link UnsupportedOperationException}.
	 * @return an iterator for all of the programs in the system
	 */
	public static Iterator<Program> getSystemPrograms() {
		return Collections.unmodifiableSet(openProgramsWeakMap.keySet()).iterator();
	}

	/**
	 * Parse an {@link Address} string which corresponds to the specified program.  
	 * Supported addresses include (order also indicates precedence):
	 * <ul>
	 * <li>Default loaded memory space (hex-offset only or with space-name, e.g., 'abcd', '0xabcd')</li>
	 * <li>Memory space-name based address (with hex-offset, e.g., 'ram:abc', see Note-1)</li>
	 * <li>External address (e.g., EXTERNAL:00001234, see Note-2)</li>
	 * <li>Stack address (e.g., Stack[0xa], Stack[-0xa], Stack[10], Stack[-10])</li>
	 * </ul>
	 * <p>
	 * NOTES:
	 * <ol>
	 * <li>Specifying only a hex offset should be restricted to a valid default address space offset
	 * to avoid having an arbitrary address space address returned.  A non-default space address
	 * should include the appropriate address space name prefix.</li>
	 * <li>If an external address is returned it does not indicate that it is defined by the 
	 * program.</li>
	 * </ol>
	 * 
	 * @param program program whose memory spaces should be considered
	 * @param addressString address string to be parsed (use of address space name prefix is
	 * case-sensitive).
	 * @return parsed address or null if parse failed
	 */
	public static Address parseAddress(Program program, String addressString) {
		Address[] addrs = program.getAddressFactory().getAllAddresses(addressString);
		if (addrs != null && addrs.length > 0) {
			return addrs[0];
		}
		Address addr = tryParseExternalAddress(addressString);
		if (addr == null) {
			addr = tryParseStackAddress(program, addressString);
		}
		return addr;
	}

	private static Address tryParseStackAddress(Program program, String addressString) {
		if (addressString.startsWith(GenericAddress.STACK_ADDRESS_PREFIX) &&
			addressString.endsWith(GenericAddress.STACK_ADDRESS_SUFFIX)) {
			try {
				AddressSpace stackSpace = program.getAddressFactory().getStackSpace();
				String offsetString = // hex (0x) or decimal
					addressString.substring(GenericAddress.STACK_ADDRESS_PREFIX.length(),
						addressString.length() - 1);
				long offset = NumericUtilities.parseLong(offsetString);
				return stackSpace.getAddress(offset);
			}
			catch (AddressOutOfBoundsException | NumberFormatException e) {
				// ignore - return null below
			}
		}
		return null;
	}

	private static Address tryParseExternalAddress(String addressString) {
		if (addressString.startsWith(EXTERNAL_ADDRESS_PREFIX)) {
			try {
				String offsetString = addressString.substring(EXTERNAL_ADDRESS_PREFIX.length());
				long offset = Long.parseLong(offsetString, 16); // hex offset only
				return AddressSpace.EXTERNAL_SPACE.getAddress(offset);
			}
			catch (AddressOutOfBoundsException | NumberFormatException e) {
				// ignore - return null below
			}
		}
		return null;
	}

	/**
	 * Get the bytes associated with the specified code unit cu 
	 * formatted as a string.  Bytes will be returned as 2-digit hex
	 * separated with a space.  Any undefined bytes will be represented by "??".
	 * @param cu code unit
	 * @return formatted byte string
	 */
	public static String getByteCodeString(CodeUnit cu) {
		int length = cu.getLength();
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < length; i++) {
			if (i != 0) {
				buffer.append(" ");
			}
			String hex;
			try {
				hex = Integer.toHexString(cu.getByte(i) & 0x0ff);
				if (hex.length() == 1) {
					buffer.append("0");
				}
			}
			catch (MemoryAccessException e) {
				hex = "??";
			}
			buffer.append(hex);
		}
		return buffer.toString();
	}

	/**
	 * Convert old function wrapped external pointers.  Migrate function to
	 * external function.
	 * @param functionSymbol old fake IAT function to be migrated
	 */
	public static void convertFunctionWrappedExternalPointer(Symbol functionSymbol) {
		if (functionSymbol.getSymbolType() != SymbolType.FUNCTION) {
			return;
		}
		Program program = functionSymbol.getProgram();
		Listing listing = program.getListing();
		SymbolTable symbolTable = program.getSymbolTable();
		Data data = listing.getDefinedDataAt(functionSymbol.getAddress());
		if (data == null || !data.isPointer()) {
			return;
		}
		Reference ref = data.getPrimaryReference(0);
		if (ref == null || !ref.isExternalReference()) {
			return;
		}
		Address extAddr = ref.getToAddress();
		Symbol s = symbolTable.getPrimarySymbol(extAddr);
		if (s == null) {
			// Bad external reference
			program.getReferenceManager().delete(ref);
			return;
		}
		Function func = (Function) functionSymbol.getObject();
		if (func == null) {
			return;
		}

		try {
			if (s.getSymbolType() != SymbolType.LABEL) {
				functionSymbol.delete();
				return;
			}
			ExternalLocation extLoc = (ExternalLocation) s.getObject();
			Function extFunc = extLoc.createFunction();
			extFunc.setComment(func.getComment());
			func.setComment(null);
			extFunc.setStackPurgeSize(func.getStackPurgeSize());
			extFunc.setCallingConvention(func.getCallingConventionName());
			extFunc.setNoReturn(func.hasNoReturn());
			extFunc.setReturnType(func.getReturnType(), SourceType.ANALYSIS);
			for (Parameter param : func.getParameters()) {
				extFunc.addParameter(param, param.getSource());
			}
			extFunc.setVarArgs(func.hasVarArgs());
			functionSymbol.delete();
		}
		catch (InvalidInputException e) {
			Msg.error(ProgramUtilities.class, "Unexpected Exception", e);
		}
		catch (DuplicateNameException e) {
			Msg.error(ProgramUtilities.class, "Unexpected Exception", e);
		}
	}

	/**
	 * Determine if a program has a single unsaved change which corresponds to an
	 * upgrade which occured during instantiation.
	 * @param program the program to be checked for an unsaved upgrade condition.
	 * @return true if program upgraded and has not been saved, else false
	 */
	public static boolean isChangedWithUpgradeOnly(Program program) {
		// The only non-undoable change is an upgrade that occurs during instantiation
		if (!program.isChanged()) {
			return false;
		}
		return !program.canUndo();
	}
}
