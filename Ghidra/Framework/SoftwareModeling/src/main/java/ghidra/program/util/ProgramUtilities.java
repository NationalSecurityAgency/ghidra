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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.*;

/**
 * General utility class that provides convenience methods
 * to deal with Program objects. 
 */
public class ProgramUtilities {

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

	public static Address parseAddress(Program program, String addressString) {
		Address[] addrs = program.parseAddress(addressString);
		if (addrs != null && addrs.length > 0) {
			return addrs[0];
		}
		String stackPrefix = "Stack[";
		if (addressString.startsWith(stackPrefix)) {
			String offsetString =
				addressString.substring(stackPrefix.length(), addressString.length() - 1);
			try {
				long offset = NumericUtilities.parseLong(offsetString);
				return program.getAddressFactory().getStackSpace().getAddress(offset);
			}
			catch (NumberFormatException e) {
				return null;
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
}
