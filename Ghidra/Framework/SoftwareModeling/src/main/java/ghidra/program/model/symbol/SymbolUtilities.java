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
import java.util.function.Consumer;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.classfinder.ClassFilter;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.*;

/**
 * Class with static methods to deal with symbol strings.
 */
public class SymbolUtilities {

	public static final int MAX_SYMBOL_NAME_LENGTH = 2000;

	//
	// The standard prefixes for default labels.
	//

	/**
	 * Default prefix for a subroutine
	 */
	private final static String DEFAULT_SUBROUTINE_PREFIX = "SUB_";
	/**
	 * Default prefix for a reference that has flow
	 * but is not a call.
	 */
	private final static String DEFAULT_SYMBOL_PREFIX = "LAB_";
	/**
	 * Default prefix for a data reference.
	 */
	private final static String DEFAULT_DATA_PREFIX = "DAT_";
	/**
	 * Default prefix for reference that is unknown.
	 */
	private final static String DEFAULT_UNKNOWN_PREFIX = "UNK_";
	/**
	 * Default prefix for an entry point.
	 */
	private final static String DEFAULT_EXTERNAL_ENTRY_PREFIX = "EXT_";
	/**
	 * Default prefix for a function.
	 */
	private final static String DEFAULT_FUNCTION_PREFIX = "FUN_";
	/**
	 * Default prefix for a reference that is offcut.
	 */
	private final static String DEFAULT_INTERNAL_REF_PREFIX = "OFF_";

	private static final String UNDERSCORE = "_";
	private final static String PLUS = "+";

	public final static int UNK_LEVEL = 0;
	public final static int DAT_LEVEL = 1;
	public final static int LAB_LEVEL = 2;
	public final static int SUB_LEVEL = 3;
	public final static int EXT_LEVEL = 5;
	public final static int FUN_LEVEL = 6;

	/**
	 * Array of default prefixes.
	 */
	private final static String[] DYNAMIC_PREFIX_ARRAY = { DEFAULT_UNKNOWN_PREFIX,
		DEFAULT_DATA_PREFIX, DEFAULT_SYMBOL_PREFIX, DEFAULT_SUBROUTINE_PREFIX,
		DEFAULT_UNKNOWN_PREFIX, DEFAULT_EXTERNAL_ENTRY_PREFIX, DEFAULT_FUNCTION_PREFIX };

	private static List<String> DYNAMIC_DATA_TYPE_PREFIXES = getDynamicDataTypePrefixes();

	/**
	 * Any dynamic label will have an address with this minimum length or longer
	 */
	private static final int MIN_LABEL_ADDRESS_DIGITS = 4;

	/**
	 * The standard prefix for denoting the ordinal
	 * values of a symbol.
	 */
	public final static String ORDINAL_PREFIX = "Ordinal_";

	/**
	 * Invalid characters for a symbol name.
	 */
	public final static char[] INVALIDCHARS = { ' ' };

	private static final Comparator<Symbol> CASE_INSENSITIVE_SYMBOL_NAME_COMPARATOR = (s1, s2) -> {
		return s1.getName().compareToIgnoreCase(s2.getName());
	};

	private static List<String> getDynamicDataTypePrefixes() {
		List<String> list = new ArrayList<>();
		ClassFilter filter = new BuiltInDataTypeClassExclusionFilter();
		List<BuiltInDataType> instances = ClassSearcher.getInstances(BuiltInDataType.class, filter);
		for (BuiltInDataType builtIn : instances) {
			String prefix = builtIn.getDefaultAbbreviatedLabelPrefix();
			if (prefix != null) {
				list.add(prefix + UNDERSCORE);
				list.add(prefix.toUpperCase() + UNDERSCORE); // to handle case insensitive
			}
		}
		return list;
	}

	public static int getOrdinalValue(String symbolName) {
		if (symbolName != null && symbolName.startsWith(ORDINAL_PREFIX)) {
			String ordinalStr = symbolName.substring(ORDINAL_PREFIX.length());
			try {
				return Integer.parseInt(ordinalStr);
			}
			catch (NumberFormatException e) {
				// not a number
			}
		}
		return -1;
	}

	/**
	 * Check for invalid characters
	 * (space, colon, asterisk, plus, bracket)
	 * in labels.
	 *
	 * @param str the string to be checked for invalid characters.
	 * @return boolean true if no invalid chars
	 */
	public static boolean containsInvalidChars(String str) {
		int len = str.length();
		for (int i = 0; i < len; i++) {
			char c = str.charAt(i);
			if (isInvalidChar(c)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Generates a default function name for a given address.
	 * @param addr the entry point of the function.
	 * @return the default generated name for the function.
	 */
	public static String getDefaultFunctionName(Address addr) {
		return DEFAULT_FUNCTION_PREFIX + getAddressString(addr);
	}

	/**
	 * Returns true if the specified name is reserved as a default external name.
	 * @param name
	 * @param addrFactory
	 * @return true if the specified name is reserved as a default external name.
	 */
	public static boolean isReservedExternalDefaultName(String name, AddressFactory addrFactory) {
		return name.startsWith(DEFAULT_EXTERNAL_ENTRY_PREFIX) &&
			parseDynamicName(addrFactory, name) != null;
	}

	/**
	 * Generates a default external name for an external function
	 * @param addr the memory address referred to by the external.
	 * @return the default generated name for the external.
	 */
	public static String getDefaultExternalFunctionName(Address addr) {
		return DEFAULT_EXTERNAL_ENTRY_PREFIX + DEFAULT_FUNCTION_PREFIX + getAddressString(addr);
	}

	/**
	 * Generates a default external name for a given external data/code location.
	 * @param addr the memory address referred to by the external.
	 * @param dt data type associated with the specified external memory address
	 * @return the default generated name for the external.
	 */
	public static String getDefaultExternalName(Address addr, DataType dt) {
		if (dt != null) {
			String prefix = dt.getDefaultLabelPrefix();
			if (prefix != null) {
				return DEFAULT_EXTERNAL_ENTRY_PREFIX + prefix + UNDERSCORE + getAddressString(addr);
			}
		}
		return DEFAULT_EXTERNAL_ENTRY_PREFIX + getAddressString(addr);
	}

	/**
	 * Returns true if the given name could match a default dynamic label (EXT, LAB, SUB, FUN, DAT)
	 * at some address.
	 * WARNING! Does not handle dynamic labels which use data-type prefixes -
	 * see {@link #isDynamicSymbolPattern(String, boolean)} for more liberal check
	 */
	public static boolean isReservedDynamicLabelName(String name, AddressFactory addrFactory) {
		String prefix = findDynamicPrefix(name);
		if (prefix == null) {
			return false;
		}
		int len = prefix.length();
		if (name.length() < len + 1) {
			return false;
		}
		return parseDynamicName(addrFactory, name) != null;
	}

	/**
	 * Validate the given symbol name: cannot be null, cannot be an empty string, cannot contain blank
	 * characters, cannot be a reserved name.
	 * @param name symbol name to be validated
	 * @throws InvalidInputException invalid or reserved name has been specified
	 */
	public static void validateName(String name) throws InvalidInputException {

		if (name == null) {
			throw new InvalidInputException("Symbol name can't be null");
		}
		if (name.length() == 0) {
			throw new InvalidInputException("Symbol name can't be empty string");
		}
		if (name.length() > MAX_SYMBOL_NAME_LENGTH) {
			throw new InvalidInputException("Symbol name exceeds maximum length of " +
				MAX_SYMBOL_NAME_LENGTH + ", length=" + name.length());
		}
		if (containsInvalidChars(name)) {
			throw new InvalidInputException("Symbol name contains invalid characters: " + name);
		}
	}

	/**
	 * Returns true if the given name starts with a possible default symbol prefix.
	 * @param name the name string to test.
	 * @return true if name starts with a know dynamic prefix
	 */
	public static boolean startsWithDefaultDynamicPrefix(String name) {
		for (String element : DYNAMIC_PREFIX_ARRAY) {
			if (name.startsWith(element)) {
				return true;
			}
		}

		for (String prefix : DYNAMIC_DATA_TYPE_PREFIXES) {
			if (name.startsWith(prefix)) {
				return true;
			}
		}

		return false;
	}

	private static String findDynamicPrefix(String name) {
		for (String element : DYNAMIC_PREFIX_ARRAY) {
			if (name.startsWith(element)) {
				return element;
			}
		}

		for (String prefix : DYNAMIC_DATA_TYPE_PREFIXES) {
			if (name.startsWith(prefix)) {
				return prefix;
			}
		}

		return null;
	}

	/**
	 * Tests if the given name is a possible dynamic symbol name.
	 * WARNING! This method should be used carefully since it will return true for
	 * any name which starts with a known dynamic label prefix or ends with an '_' 
	 * followed by a valid hex value.
	 * @param name the name to test
	 * @param caseSensitive true if case matters.
	 * @return true if name is a possible dynamic symbol name, else false
	 */
	public static boolean isDynamicSymbolPattern(String name, boolean caseSensitive) {

		name = caseSensitive ? name : name.toUpperCase();
		if (startsWithDefaultDynamicPrefix(name)) {
			return true;
		}

		// TODO: This appears that it incorrectly match our de-duped
		// naming convention of adding the address to the end of a base name
		int lastIndex = name.lastIndexOf('_');
		if (lastIndex <= 0) {
			return false;
		}
		String suffix = name.substring(lastIndex + 1);
		if (suffix.length() < 3 || suffix.length() > 16) {
			return false;
		}
		return isHexDigits(suffix);
	}

	private static boolean isHexDigits(String suffix) {
		for (int i = 0; i < suffix.length(); i++) {
			char c = suffix.charAt(i);
			if (!isHexDigit(c)) {
				return false;
			}
		}
		return true;
	}

	private static boolean isHexDigit(char c) {
		if (c >= '0' && c <= '9') {
			return true;
		}
		if (c >= 'a' && c <= 'f') {
			return true;
		}
		if (c >= 'A' && c <= 'F') {
			return true;
		}
		return false;
	}

	/**
	 * Returns true if the specified char
	 * is not valid for use in a symbol name
	 * @param c the character to be tested as a valid symbol character.
	 * @return return true if c is an invalid char within a symbol name, else false
	 */
	public static boolean isInvalidChar(char c) {
		if (c < ' ') { // non-printable ASCII
			return true;
		}

		for (char element : INVALIDCHARS) {
			if (c == element) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Removes from the given string any invalid characters or replaces
	 * them with underscores.
	 *
	 * For example:
	 * given "a:b*c", the return value would be "a_b_c"
	 *
	 * @param str the string to have invalid chars converted to underscores or removed.
	 * @param replaceWithUnderscore - true means replace the invalid
	 * chars with underscore. if false, then just drop the invalid chars
	 * @return modified string
	 */
	public static String replaceInvalidChars(String str, boolean replaceWithUnderscore) {
		if (str == null) {
			return null;
		}
		int len = str.length();
		StringBuffer buf = new StringBuffer(len);
		for (int i = 0; i < len; ++i) {
			char c = str.charAt(i);
			if (isInvalidChar(c)) {
				if (replaceWithUnderscore) {
					buf.append(UNDERSCORE);
				}
			}
			else {
				buf.append(c);
			}
		}
		return buf.toString();
	}

	/**
	 * Create a dynamic label name for an offcut reference.
	 * @param addr the address at which to create an offcut reference name.
	 * @return dynamic offcut label name
	 */
	public static String getDynamicOffcutName(Address addr) {
		if (addr != null) {
			return DEFAULT_INTERNAL_REF_PREFIX + getAddressString(addr);
		}
		return null;
	}

	/**
	 * Create a name for a dynamic symbol with a 3-letter prefix based upon reference level
	 * and an address.  Acceptable referenceLevel's are: 
	 * {@link #UNK_LEVEL}, {@link #DAT_LEVEL}, {@link #LAB_LEVEL}, {@link #SUB_LEVEL}, 
	 * {@link #EXT_LEVEL}, {@link #FUN_LEVEL}.
	 * @param referenceLevel the type of reference for which to create a dynamic name.
	 * @param addr the address at which to create a dynamic name.
	 * @return dynamic symbol name
	 */
	public static String getDynamicName(int referenceLevel, Address addr) {
		if (addr != null) {
			return DYNAMIC_PREFIX_ARRAY[referenceLevel] + getAddressString(addr);
		}
		return null;
	}

	/**
	 * Create a name for a dynamic symbol.
	 * @param program the current program
	 * @param addr the address of the symbol for which to generate a name
	 * @return a name for the symbol at the given address
	 */
	public static String getDynamicName(Program program, Address addr) {
		if (addr == null || !addr.isMemoryAddress()) {
			return null;
		}

		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitContaining(addr);
		int refLevel = program.getReferenceManager().getReferenceLevel(addr);
		if (codeUnit == null) {
			return getDynamicName(refLevel, addr);
		}

		if (codeUnit instanceof Instruction) {
			return getDynamicInstructionName(program, (Instruction) codeUnit, addr, refLevel);
		}

		// must be a data
		return getDynamicDataName((Data) codeUnit, addr, refLevel);
	}

	private static String getDynamicDataName(Data data, Address address, int refLevel) {

		Address codeUnitAddress = data.getMinAddress();
		long diff = address.subtract(codeUnitAddress);

		boolean isString = data.hasStringValue();

		//
		// Data member
		//
		if (!isString) {
			int n = data.getNumComponents();
			if (n > 0 && diff > 0) { // only when there are children and there is an offcut
				Data data2 = data.getPrimitiveAt((int) diff);
				if (data2 == null) {
					data2 = data;
				}
				long datOffset = address.subtract(data2.getMinAddress());
				return (datOffset == 0 ? data2.getPathName()
						: data2.getPathName() + PLUS + datOffset);
			}
		}

		//
		// Non-data member
		//
		Address normalizedAddress = normalizeSegmentedAddress(data, address);
		if (diff != 0) {
			return generateOffcutDataName(data, normalizedAddress, (int) diff, refLevel, isString);
		}

		String prefix = data.getDefaultLabelPrefix(DataTypeDisplayOptions.DEFAULT);
		if (prefix != null) {
			return prefix + UNDERSCORE + getAddressString(normalizedAddress);
		}

		//
		// no prefix given--use default dynamic name
		//
		return getDynamicName(refLevel, normalizedAddress);
	}

	private static String generateOffcutDataName(Data data, Address address, int offcutOffset,
			int refLevel, boolean isString) {

		DataType dataType = data.getDataType();
		String prefix = dataType.getDefaultOffcutLabelPrefix(data, data, data.getLength(),
			DataTypeDisplayOptions.DEFAULT, offcutOffset);

		//
		// Strings take precedence
		//
		if (isString) {
			// we draw strings with their real address instead of with an offset
			return prefix + UNDERSCORE + getAddressString(address);
		}

		//
		// If there is a label at the CodeUnit start, then we want to be based upon that, except
		// in special cases, like String data
		//
		String offcutText = PLUS + Integer.toString(offcutOffset);
		Symbol symbol = data.getPrimarySymbol();
		if (symbol != null && !symbol.isDynamic()) {
			return symbol.getName() + offcutText;
		}

		//
		// No symbol, use the default prefix
		//
		Address minAddress = address.subtract(offcutOffset);
		if (prefix != null) {
			return prefix + UNDERSCORE + getAddressString(minAddress) + offcutText;
		}

		//
		// no prefix given--use default dynamic name
		//
		return getDynamicName(refLevel, minAddress) + offcutText;
	}

	private static String getDynamicInstructionName(Program program, Instruction instruction,
			Address address, int refLevel) {

		Address codeUnitAddress = instruction.getMinAddress();
		long diff = address.subtract(codeUnitAddress);
		if (diff != 0) {
			return getDyanmicOffcutInstructionName(instruction, codeUnitAddress, diff);
		}

		Function function = program.getFunctionManager().getFunctionAt(codeUnitAddress);
		if (function != null) {
			return DEFAULT_FUNCTION_PREFIX + getAddressString(codeUnitAddress);
		}

		if (refLevel == SUB_LEVEL) {
			return DEFAULT_SUBROUTINE_PREFIX + getAddressString(codeUnitAddress);
		}

		if (refLevel == EXT_LEVEL) {
			return DEFAULT_EXTERNAL_ENTRY_PREFIX + getAddressString(codeUnitAddress);
		}

		return DEFAULT_SYMBOL_PREFIX + getAddressString(codeUnitAddress);
	}

	private static String getDyanmicOffcutInstructionName(Instruction instruction,
			Address codeUnitAddress, long diff) {
		String offcutText = PLUS + Long.toString(diff);

		//
		// If there is a label at the CodeUnit start, then we want to be based upon that, except
		// in special cases, like String data
		//
		Symbol symbol = instruction.getPrimarySymbol();
		if (symbol != null && !symbol.isDynamic()) {
			return symbol.getName() + offcutText;
		}
		return DEFAULT_SYMBOL_PREFIX + getAddressString(codeUnitAddress) + offcutText;
	}

	/** normalize to code unit address (in case we have segmented addresses) */
	private static Address normalizeSegmentedAddress(CodeUnit codeUnit, Address address) {
		if (!(address instanceof SegmentedAddress)) {
			return address;
		}

		SegmentedAddress segmentedAddress = (SegmentedAddress) address;
		SegmentedAddress codeUnitAddress = (SegmentedAddress) codeUnit.getAddress();
		return segmentedAddress.normalize(codeUnitAddress.getSegment());
	}

	/**
	 * Parse a dynamic name and return its address or null if unable to parse.
	 * @param factory address factory
	 * @param name the dynamic label name to parse into an address.
	 * @return address corresponding to symbol name if it satisfies possible dynamic naming
	 * or null if unable to parse address fro name
	 */
	public static Address parseDynamicName(AddressFactory factory, String name) {

		// assume dynamic names will naver start with an underscore
		if (name.startsWith(UNDERSCORE)) {
			return null;
		}

		String[] pieces = name.split(UNDERSCORE);
		if (pieces.length < 2) { // if we have less than two pieces, then this is not a dynamic name.
			return null;
		}

		String addressOffsetString = pieces[pieces.length - 1];

		AddressSpace space = findAddressSpace(factory, pieces);
		if (space == null) {
			space = factory.getDefaultAddressSpace();
		}

		// Only consider address values which meet the meet the minimum padding behavior
		if (addressOffsetString.length() < MIN_LABEL_ADDRESS_DIGITS) {
			return null;
		}

		/**
		 * If we are dealing with segmented addresses, then the address is really composed of the
		 * last two pieces.
		 */
		if (space instanceof SegmentedAddressSpace) {
			addressOffsetString = pieces[pieces.length - 2] + ':' + addressOffsetString;
		}

		try {
			return space.getAddress(addressOffsetString);
		}
		catch (AddressFormatException e) {
			// return null instead
		}
		return null;
	}

	/**
	 * Returns the addressSpace that matches the largest range of parsed pieces, ignoring the first and
	 * last piece (which can't be part of an addressSpace name).  In other words if the array of strings
	 * passed in is {"a","b","c","d","e"}, it will test for addresSpaces named "b_c_d", then "c_d", and
	 * finally "d".
	 * @param factory the address factory containing the valid addressSpaces.
	 * @param pieces the array of parsed label pieces
	 * @return The addressSpace the matches the biggest string, or the default space if no match is found.
	 */
	private static AddressSpace findAddressSpace(AddressFactory factory, String[] pieces) {
		// ignore the last piece, since that has to be part of the offset.

		int start = 1;
		int end = pieces.length - 2;
		if (pieces[end].length() == 0) { // if last piece is empty string, then it is not part of spaceName;
			end--;
		}

		while (start <= end) {
			String addrSpaceName = buildSpaceName(pieces, start, end);
			AddressSpace space = factory.getAddressSpace(addrSpaceName);
			if (space != null) {
				return space;
			}
			start++;
		}

		return factory.getDefaultAddressSpace();
	}

	private static String buildSpaceName(String[] pieces, int start, int end) {
		StringBuffer buf = new StringBuffer();
		buf.append(pieces[start]);
		for (int i = start + 1; i <= end; i++) {
			buf.append(UNDERSCORE);
			buf.append(pieces[i]);
		}
		return buf.toString();
	}

	public static String getAddressString(Address addr) {
		String addrString = addr.toString();
		addrString = addrString.replace(':', '_');
		return addrString;
	}

	public static String getDefaultParamName(int ordinal) {
		return Function.DEFAULT_PARAM_PREFIX + (ordinal + 1);
	}

	public static boolean isDefaultParameterName(String name) {
		if (name == null || name.length() == 0) {
			return true;
		}
		if (name.startsWith(Function.DEFAULT_PARAM_PREFIX)) {
			String tail = name.substring(Function.DEFAULT_PARAM_PREFIX.length());
			try {
				Integer.parseInt(tail);
				return true;
			}
			catch (NumberFormatException e) {
				// not a number
			}
		}
		return false;
	}

	public static String getDefaultLocalName(Program program, int stackOffset, int firstUseOffset) {
		boolean stackGrowsNegative = program.getCompilerSpec().stackGrowsNegative();
		boolean reservedArea = stackGrowsNegative ? (stackOffset >= 0) : (stackOffset < 0);
		stackOffset = Math.abs(stackOffset);
		String name = (reservedArea ? Function.DEFAULT_LOCAL_RESERVED_PREFIX
				: Function.DEFAULT_LOCAL_PREFIX) +
			Integer.toHexString(stackOffset);
		if (firstUseOffset != 0) {
			name += UNDERSCORE + Integer.toString(firstUseOffset);
		}
		return name;
	}

	public static String getDefaultLocalName(Program program, VariableStorage storage,
			int firstUseOffset) {

		if (storage.isHashStorage()) {
			String name = Function.DEFAULT_LOCAL_TEMP_PREFIX;
			long hash = storage.getFirstVarnode().getOffset();
			if (hash != 0) {
				name += Long.toHexString(hash);
			}
			else {
				name += UNDERSCORE + Integer.toString(firstUseOffset);
			}
			return name;
		}

		if (storage.isStackStorage()) {
			return getDefaultLocalName(program, storage.getStackOffset(), firstUseOffset);
		}

		StringBuilder buffy = new StringBuilder(Function.DEFAULT_LOCAL_PREFIX);
		boolean first = true;
		for (Varnode v : storage.getVarnodes()) {
			if (!first) {
				buffy.append('_');
			}
			Address addr = v.getAddress();
			if (addr.isStackAddress()) {
				int absStackOffset = Math.abs((int) addr.getOffset());
				buffy.append(Integer.toHexString(absStackOffset));
			}
			else {
				Register reg = program.getRegister(v);
				if (reg != null) {
					buffy.append(reg.getName());
				}
				else {
					buffy.append(getVariableAddressString(addr));
				}
			}
		}
		if (firstUseOffset != 0) {
			buffy.append('_');
			buffy.append(Integer.toString(firstUseOffset));
		}
		return buffy.toString();
	}

	public static boolean isDefaultLocalName(Program program, String name,
			VariableStorage storage) {
		if (name == null || name.length() == 0) {
			return true;
		}
		if (storage == VariableStorage.BAD_STORAGE) {
			return false;
		}
		if (storage.isStackStorage()) {
			return isDefaultLocalStackName(name);
		}
		// TODO: we may need to identify the general pattern of default names
		String defaultName = getDefaultLocalName(program, storage, 0);
		return name.startsWith(defaultName);
	}

	private static String getVariableAddressString(Address addr) {
		return addr.getAddressSpace().getName() + Long.toHexString(addr.getOffset());
	}

	public static boolean isDefaultLocalStackName(String name) {
		if (name == null || name.length() == 0) {
			return true;
		}
		if (name.startsWith(Function.DEFAULT_LOCAL_PREFIX)) {
			String tail = name.substring(Function.DEFAULT_LOCAL_PREFIX.length());
			tail = removeFirstUseOffset(tail);
			try {
				Integer.parseInt(tail, 16);
				return true;
			}
			catch (NumberFormatException e) {
				// not a number
			}
		}
		else if (name.startsWith(Function.DEFAULT_LOCAL_RESERVED_PREFIX)) {
			String tail = name.substring(Function.DEFAULT_LOCAL_RESERVED_PREFIX.length());
			tail = removeFirstUseOffset(tail);
			try {
				Integer.parseInt(tail, 16);
				return true;
			}
			catch (NumberFormatException e) {
				// not a number
			}
		}
		return false;
	}

	private static String removeFirstUseOffset(String str) {
		int index = str.lastIndexOf('_');
		if (index < 0) {
			return str;
		}
		try {
			Integer.parseInt(str.substring(index + 1));
			return str.substring(0, index);
		}
		catch (NumberFormatException e) {
			// not a number
		}
		return str;
	}

	/**
	 * Creates the standard symbol name for symbols that have the addresses appended to the 
	 * name following an "@" character in order to make it unique.
	 * @param name the "true" name of the symbol
	 * @param address the address to be appended
	 * @return the name with the address appended.
	 */
	public static String getAddressAppendedName(String name, Address address) {
		return getAddressAppendedName(name, address, "@");
	}

	/**
	 * Creates the a symbol name for symbols that have the addresses appended to the 
	 * name in order to make it unique.
	 * @param name the "true" name of the symbol
	 * @param address the address to be appended
	 * @param suffixSeparator "@" or "_"
	 * @return the name with the address appended.
	 */
	private static String getAddressAppendedName(String name, Address address,
			String suffixSeparator) {
		return name + suffixSeparator + getAddressString(address);
	}

	/**
	 * Gets the base symbol name regardless of whether or not the address has been appended.
	 * @param symbol the symbol to get the clean name for.
	 * @return the base symbol name where the {@literal "@<address>"} has been stripped away if it exists.
	 */
	public static String getCleanSymbolName(Symbol symbol) {
		return getCleanSymbolName(symbol.getName(), symbol.getAddress());
	}

	/**
	 * Gets the base symbol name regardless of whether or not the address has been appended 
	 * using either the standard "@" separator, or the less preferred "_" separator.  The
	 * address string extension must match that which is produced by the 
	 * {@link #getAddressString(Address)} method for it to be recognized.
	 * @param symbolName a symbol name to get the clean name for.
	 * @param address the symbol's address
	 * @return the base symbol name where the {@literal "@<address>"} has been stripped away if it exists.
	 */
	public static String getCleanSymbolName(String symbolName, Address address) {

		int indexOfAt = symbolName.lastIndexOf("@");
		int indexOfUnderscore = symbolName.lastIndexOf("_");

		if (indexOfAt < 1 && indexOfUnderscore < 1) {
			return symbolName;
		}

		if (indexOfAt > indexOfUnderscore) {
			// Check for possible use of "@"
			String potentialBaseName = symbolName.substring(0, indexOfAt);
			if (symbolName.equals(getAddressAppendedName(potentialBaseName, address, "@"))) {
				return potentialBaseName;
			}
			return symbolName;
		}

		// Check for possible use of "_"
		String potentialBaseName = symbolName.substring(0, indexOfUnderscore);
		if (symbolName.equals(getAddressAppendedName(potentialBaseName, address, "_"))) {
			return potentialBaseName;
		}
		return symbolName;
	}

	/**
	 * Returns display text suitable for describing in the GUI the {@link SymbolType} of the
	 * given symbol
	 *
	 * @param symbol The symbol from which to get the SymbolType
	 * @return a display string for the SymbolType
	 */
	public static String getSymbolTypeDisplayName(Symbol symbol) {
		if (symbol == null) {
			return null;
		}

		SymbolType symType = symbol.getSymbolType();
		if (symType == SymbolType.LABEL) {
			if (symbol.isExternal()) {
				return "External Data";
			}
			if (!symbol.isPrimary()) {
				Program program = symbol.getProgram();
				Symbol primary = program.getSymbolTable().getPrimarySymbol(symbol.getAddress());
				if (primary != null && primary.getSymbolType() == SymbolType.FUNCTION) {
					return "Function";
				}
			}
			Object obj = symbol.getObject();
			if (obj instanceof Instruction) {
				return "Instruction Label";
			}
			else if (obj != null) {
				return "Data Label";
			}
		}
		else if (symType == SymbolType.FUNCTION) {
			if (symbol.isExternal()) {
				return "External Function";
			}

			Function func = (Function) symbol.getObject();
			if (func == null) {
				return null; // symbol deleted
			}
			if (func.isThunk()) {
				return "Thunk Function";
			}
			return "Function";
		}
		if (symbol.isExternal()) {
			return "External " + symType;
		}
		return symType.toString();
	}

	/**
	 * Returns the unique global label or function symbol with the given name. Also, logs if there
	 * is not exactly one symbol with that name.
	 *
	 * @param program the program to search.
	 * @param symbolName the name of the global label or function symbol to search.
	 * @param errorConsumer the object to use for reporting errors via it's accept() method.
	 * @return symbol if a unique label/function symbol with name is found or null
	 */
	public static Symbol getExpectedLabelOrFunctionSymbol(Program program, String symbolName,
			Consumer<String> errorConsumer) {
		List<Symbol> symbols = program.getSymbolTable().getLabelOrFunctionSymbols(symbolName, null);
		if (symbols.size() == 1) {
			return symbols.get(0);
		}

		if (symbols.isEmpty()) {
			errorConsumer.accept(symbolName + " symbol not found!");
		}
		else {
			errorConsumer.accept("Multiple " + symbolName + " symbols found!");
		}

		return null;
	}

	/**
	 * Returns the unique global label or function symbol with the given name. Also, logs if there
	 * is more than one symbol with that name.
	 *
	 * @param program the program to search.
	 * @param symbolName the name of the global label or function symbol to search.
	 * @param errorConsumer the object to use for reporting errors via it's accept() method.
	 * @return symbol if a unique label/function symbol with name is found or null
	 */
	public static Symbol getLabelOrFunctionSymbol(Program program, String symbolName,
			Consumer<String> errorConsumer) {
		List<Symbol> symbols = program.getSymbolTable().getLabelOrFunctionSymbols(symbolName, null);
		if (symbols.size() == 1) {
			return symbols.get(0);
		}

		if (symbols.size() > 1) {
			errorConsumer.accept("Multiple " + symbolName + " symbols found!");
		}

		return null;
	}

	/**
	 * Create label symbol giving preference to non-global symbols.  An existing function symbol
	 * may be returned.  If attempting to create a global symbol and the name already exists 
	 * at the address no symbol will be created and null will be returned.  
	 * If attempting to create a non-global symbol, which does not exist,
	 * and a global symbol does exist with same name its namespace will be changed. 
	 * @param program program within which the symbol should be created
	 * @param address memory address where symbol should be created
	 * @param namespace symbol namespace or null for global
	 * @param name symbol name
	 * @param source symbol source type
	 * @return new or existing label or function symbol or null if creating a global symbol
	 * whose name already exists at address
	 * @throws InvalidInputException if invalid symbol name provided
	 */
	public static Symbol createPreferredLabelOrFunctionSymbol(Program program, Address address,
			Namespace namespace, String name, SourceType source) throws InvalidInputException {

		try {
			if (!address.isMemoryAddress()) {
				throw new IllegalArgumentException("expected memory address");
			}
			if (namespace == null) {
				namespace = program.getGlobalNamespace();
			}

			SymbolTable symbolTable = program.getSymbolTable();

			// check for symbol already existing at address
			Symbol symbol = symbolTable.getSymbol(name, address, namespace);
			if (symbol != null) {
				return symbol;
			}

			if (namespace.isGlobal()) {
				// do not add global symbol if same name already exists at address
				for (Symbol s : program.getSymbolTable().getSymbols(address)) {
					if (name.equals(s.getName())) {
						return null;
					}
				}
			}
			else {
				// change namespace on global symbol with same name
				symbol = symbolTable.getGlobalSymbol(name, address);
				if (symbol != null) {
					symbol.setNamespace(namespace);
					return symbol;
				}
			}

			// create new symbol if needed
			return symbolTable.createLabel(address, name, namespace, source);
		}
		catch (DuplicateNameException | CircularDependencyException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * Returns a comparator for symbols.  The comparison is based upon the name.  This call
	 * replaces the former <code>compareTo</code> method on Symbol.  This comparator returned here
	 * is case-insensitive.
	 * 
	 * @return the comparator
	 */
	public static Comparator<Symbol> getSymbolNameComparator() {
		return CASE_INSENSITIVE_SYMBOL_NAME_COMPARATOR;
	}
}
