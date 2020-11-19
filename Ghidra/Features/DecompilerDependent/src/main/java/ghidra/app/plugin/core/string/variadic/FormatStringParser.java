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
package ghidra.app.plugin.core.string.variadic;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Class for parsing a variadic function's format String to determine the proper
 * number of arguments and their DataTypes. It analyzes format strings from variadic functions. 
 * Parses format strings adhering to docs https://pubs.opengroup.org/onlinepubs/009695399/functions/fprintf.html
 * and https://en.cppreference.com/w/c/io/fscanf. If a format string doesn't adhere properly 
 * to what is specified in the docs, the string will not continue to be parsed since this is 
 * undefined behavior.
 * <br>
 * The standard C formats may make optional use of the following extended precision types
 * which may be defined as a {@link TypeDef} the appropriate Datatype implementation. 
 * If a format string is encountered which refers to one of these types which has not 
 * previously been defined, a TypeDef will be fabricated although it may not be correct.
 * <ul>
 * <li>intmax_t - maximum sized signed integer (default: long long)</li>
 * <li>uintmax_t - maximum size unsigned integer (default: unsigned long long)</li>
 * <li>size_t - unsigned integer type corresponding to sizeof (default: varies) </li>
 * <li>ptrdiff_t - signed integer type (default: varies) </li>
 * </ul>
 */
public class FormatStringParser {

	public static final String INTMAX_T_NAME = "intmax_t";
	public static final String UINTMAX_T_NAME = "uintmax_t";
	public static final String SIZE_T_NAME = "size_t";
	public static final String PTRDIFF_T_NAME = "ptrdiff_t";

	private DataTypeManager dataTypeManager;

	private TypeDef intmax_t;
	private TypeDef uintmax_t;
	private TypeDef size_t;
	private TypeDef ptrdiff_t;

	/**
	 * Constructor for FormatStringParser.
	 * <br>
	 * NOTE: Warning messages will be logged once per instantiation when 
	 * appropriate required TypeDef (intmax_t, uintmax_t, size_t, ptrdif_t)
	 * has not been predefined.
	 * 
	 * @param program currentProgram
	 */
	public FormatStringParser(Program program) {
		this.dataTypeManager = program.getDataTypeManager();
	}

	/**
	 * This function takes in a format string and returns List of Strings each holding 
	 * format data. Each String is a substring of the given format string that corresponds to one
	 * or more DataTypes. These DataTypes determine which arguments need to be given to the variadic
	 * function. For instance, given the format String "%d %4.2s", this function will return 
	 * the List ["d", "4.2s"]
	 * 
	 * @param formatString format String
	 * @return List of substrings of formatStr
	 */
	private List<String> parseFormatString(String formatString) {

		List<String> formatArgumentList = new ArrayList<>();
		String current = "";
		for (int i = 0; i < formatString.length(); i++) {
			char c = formatString.charAt(i);
			if (c == '%') {
				if (emitPercent(formatString, i)) {
					++i;
				}
				else {
					++i;
					c = formatString.charAt(i);
					while (!isConversionSpecifier(c)) {
						current += c;
						++i;
						if (i >= formatString.length()) {
							return null;
						}
						c = formatString.charAt(i);
					}
					formatArgumentList.add(current + c);
					current = "";
				}
			}
		}
		return formatArgumentList;
	}

	/**
	 * Takes in a single String from parseFormatString's output List and converts it to
	 * the corresponding FormatArgument(s) and populates the formatArgumentList List.
	 * isOutputType is true when using a format string for a function that "outputs"
	 * Strings (e.g., printf, fprintf, etc.). When it's false, it evaluates the
	 * String's data types as if the function "inputs" Strings (e.g., scanf)
	 * 
	 * @param formatString       Format String
	 * @param formatArgumentList   List of FormatArgument that will be written to
	 * @param isOutputType Type of variadic function
	 * @return True if format string successfully parsed
	 */
	private boolean convertToFormatArguments(String formatString,
			List<FormatArgument> formatArgumentList, boolean isOutputType) {

		FormatParsingData data = new FormatParsingData();
		for (int i = 0; i < formatString.length(); i++) {
			char c = formatString.charAt(i);
			i = preprocessChar(formatString, i, isOutputType);
			if (i == -1) {
				return false;
			}
			if (isFlag(c)) {
				continue;
			}
			if (data.getLengthModifier() != null) {
				return addArgumentWithModifier(c, data, formatArgumentList);
			}
			data.setLengthModifier(detectLengthModifier(c));
			if (data.getLengthModifier() == null) {
				data.setConversionSpecifier(detectConversionSpecifier(c));
				if (data.getConversionSpecifier() != null) {
					if (!verifyConversionPair(data.getLengthModifier(),
						data.getConversionSpecifier())) {
						return false;
					}
					formatArgumentList.add(new FormatArgument(data.getLengthModifier(),
						data.getConversionSpecifier()));
					return true;
				}
				// If length modifier and conversion specs aren't present
				// and we get an unknown char, format string is invalid
				if (data.isPrecisionComplete()) {
					return false;
				}
				if (!Character.isDigit(c) && c != '.' && c != '*') {
					return false;
				}
				if (isOutputType) {
					// At this point c is either a number, '*', or '.'
					i = handleOutputConversionArgument(formatString, i, data, formatArgumentList);
					if (i == -1) {
						return false;
					}
				}
				else {
					i = handleInputConversionArgument(formatString, i, data, formatArgumentList);
					if (i == -1) {
						return false;
					}
				}
			}
			else if (i + 1 < formatString.length()) {
				i = initiateLengthModifierExtension(formatString, i, data);
			}
		}
		return true;
	}

	private int preprocessChar(String formatString, int i, boolean isOutputType) {

		char c = formatString.charAt(i);
		if (c == '$') {
			return -1;
		}
		if (isFlag(c)) {
			if (!isOutputType) {
				return -1;
			}
			i = skipFlags(formatString, i);
		}
		return i;
	}

	private int initiateLengthModifierExtension(String formatString, int i,
			FormatParsingData data) {
		String tmpLengthModifier =
			extendLengthModifier(data.getLengthModifier(), formatString.charAt(i + 1));
		if (tmpLengthModifier != null) {
			++i;
			data.setLengthModifier(tmpLengthModifier);
		}
		return i;
	}

	private boolean addArgumentWithModifier(char c, FormatParsingData data,
			List<FormatArgument> formatArgumentList) {
		data.setConversionSpecifier(detectConversionSpecifier(c));
		if ((data.getConversionSpecifier() == null) ||
			!(verifyConversionPair(data.getLengthModifier(), data.getConversionSpecifier()))) {
			return false; // Problem with format string
		}
		formatArgumentList
				.add(new FormatArgument(data.getLengthModifier(), data.getConversionSpecifier()));
		return true;

	}

	private int handleOutputConversionArgument(String formatString, int i, FormatParsingData data,
			List<FormatArgument> formatArgumentList) {
		char c = formatString.charAt(i);
		if (!data.isPrecisionComplete() && !data.isFieldWidthComplete() && c != '.') {
			if (c == '*') {
				formatArgumentList.add(new FormatArgument(null, "*"));
			}
			else {
				i = skipIntegers(formatString, i);
			}
			if (i == -1) {
				return i;
			}
			data.setFieldWidthComplete(true);
		}
		else if (data.isFieldWidthComplete() && c != '.') {
			return -1;
		}
		else if (!data.isPrecisionComplete() && c == '.') {
			if (i + 1 < formatString.length() && formatString.charAt(i + 1) == '*') {
				++i;
				formatArgumentList.add(new FormatArgument(null, "*"));
			}
			else {
				i = skipIntegers(formatString, i + 1);
			}
			if (i == -1) {
				return i;
			}
			data.setPrecisionComplete(true);
		}
		else {
			return -1;
		}
		return i;
	}

	private int handleInputConversionArgument(String formatString, int i, FormatParsingData data,
			List<FormatArgument> formatArgumentList) {
		char c = formatString.charAt(i);
		if (c == '*') {
			formatArgumentList.add(new FormatArgument(null, "*"));
		}
		else if (Character.isDigit(c)) {
			i = skipIntegers(formatString, i + 1);
			if (i == -1) {
				return i;
			}
			data.setPrecisionComplete(true);
		}
		else {
			return -1;
		}
		return i;
	}

	/**
	 * Takes in a String and converts it to a List of FormatArgument with each FormatArgument
	 * corresponding to an additional argument. isOutputType is true when using a
	 * format string for output data types (e.g. printf, fprintf, etc.). When it's
	 * false, it evaluates the String's data types as if they were input types (e.g.
	 * scanf)
	 * 
	 * @param formatString format String
	 * @param isOutputType Type of variadic function
	 * @return List of FormatArgument
	 */

	public List<FormatArgument> convertToFormatArgumentList(String formatString,
			boolean isOutputType) {

		if (formatString == null) {
			return null;
		}
		List<String> formatStrArgumentList = parseFormatString(formatString);
		if (formatStrArgumentList == null) {
			return null;
		}
		List<FormatArgument> formatArgumentList = new ArrayList<>();
		for (String formatStrArgument : formatStrArgumentList) {
			boolean status =
				convertToFormatArguments(formatStrArgument, formatArgumentList, isOutputType);
			if (!status) {
				if (formatStrArgumentList.stream()
						.filter(str -> str.contains("$"))
						.findAny()
						.isPresent()) {
					return analyzeFormatStringWithParameters(formatString);
				}
				return null;
			}
		}
		return formatArgumentList.contains(null) ? null : formatArgumentList;
	}

	/**
	 * 
	 * Handles format Strings with parameters. In this parser, we define a format
	 * String parameter to be an integer n provided in the form: "%n$" or "*n$", where n is
	 * the index of the referred argument. If a placeholder uses a format
	 * argument parameter, all other placeholders must also have a parameter. Also,
	 * all gaps between format argument indices are not supported. For instance, if
	 * the first and third arguments are used, there must also be a parameter for a
	 * second argument. Any parameter pattern beginning with % or * and ending with
	 * $ must have integer in between. Failing to adhere by the format string
	 * parameter requirements returns null.
	 * 
	 * @param formatString format String
	 * @return List of FormatArgument
	 * 
	 * 
	 *         TODO: What if multiple conversion specs refer to the same placeholder
	 *         with different types? Ex: "%1$*1$x" (uses unsigned int and int)
	 *         Currently just overwrites previous type
	 * 
	 */
	public List<FormatArgument> analyzeFormatStringWithParameters(String formatString) {

		FormatParsingData data = new FormatParsingData();
		Map<Integer, FormatArgument> formatArgumentMap = new HashMap<>();
		for (int i = 0; i < formatString.length(); i++) {
			char c = formatString.charAt(i);
			if (c == ' ') {
				continue;
			}
			if (c == '%') {
				if (emitPercent(formatString, i)) {
					++i;
				}
				else {
					data.setInConversion(true);
					data.clearData();
					data.setParameterIndex(locateParameterIndex(formatString, i));
					if (data.getParameterIndex() == 0) {
						return null; // $ operand number is required
					}
					i += Integer.toString(data.getParameterIndex()).length() + 1; // i should be at $
					if (isFlag(formatString.charAt(i + 1))) {
						i = skipFlags(formatString, i + 1);
					}
					continue;
				}
			}
			if (data.isInConversion()) {
				if (data.getLengthModifier() != null) {
					data.setConversionSpecifier(detectConversionSpecifier(c));
					if (data.getConversionSpecifier() == null) {
						return null; // Problem with format string
					}
					formatArgumentMap.put(data.getParameterIndex(), new FormatArgument(
						data.getLengthModifier(), data.getConversionSpecifier()));
					data.setInConversion(false);
					continue;
				}
				data.setLengthModifier(detectLengthModifier(c));
				if (data.getLengthModifier() == null) {
					i = searchWithNullModifier(formatString, i, data, formatArgumentMap);
					if (i == -1) {
						return null;
					}
				}
			}
		}
		return convertMapToList(formatArgumentMap);
	}

	// Continue format String conversion parsing for when the length modifier is null
	private int searchWithNullModifier(String formatString, int i, FormatParsingData data,
			Map<Integer, FormatArgument> formatArgumentMap) {
		char c = formatString.charAt(i);
		data.setConversionSpecifier(detectConversionSpecifier(c));
		if (data.getConversionSpecifier() != null) {
			formatArgumentMap.put(data.getParameterIndex(),
				new FormatArgument(data.getLengthModifier(), data.getConversionSpecifier()));
			data.setInConversion(false);
		}
		else {
			if (data.isPrecisionComplete()) {
				return -1;
			}
			if (!Character.isDigit(c) && c != '.' && c != '*') {
				return -1;
			}
			// At this point c is either a number, '*', or '.'
			if (!data.isPrecisionComplete() && !data.isFieldWidthComplete() && c != '.') {
				i = handleOutputConversionForParameters(formatString, i, data, formatArgumentMap);
				if (i == -1) {
					return -1;
				}
			}
			else if (data.isFieldWidthComplete() && c != '.') {
				return -1;
			}
			else if (!data.isPrecisionComplete() && c == '.') {
				i = handlePrecisionForParameters(formatString, i, data, formatArgumentMap);
				if (i == -1) {
					return -1;
				}
			}
			else {
				return -1;
			}
		}
		return i;
	}

	// Takes care of optional precision indicated by a period ('.') and followed by an
	// asterick or series of integers
	private int handlePrecisionForParameters(String formatString, int i, FormatParsingData data,
			Map<Integer, FormatArgument> formatArgumentMap) {

		if (i + 1 < formatString.length() && formatString.charAt(i + 1) == '*') {
			++i;
			int precisionIdx = locateParameterIndex(formatString, i);
			if (precisionIdx == 0) {
				return -1;
			}
			i += Integer.toString(precisionIdx).length() + 1;
			// i should be at $
			formatArgumentMap.put(precisionIdx, new FormatArgument(null, "d"));
		}
		else {
			i = skipIntegers(formatString, i + 1); // i should be at last number
			if (i == -1) {
				return -1;
			}
		}
		data.setPrecisionComplete(true);
		return i;
	}

	private int handleOutputConversionForParameters(String formatString, int i,
			FormatParsingData data, Map<Integer, FormatArgument> formatArgumentMap) {
		char c = formatString.charAt(i);
		if (c == '*') {
			int fieldWidthIdx = locateParameterIndex(formatString, i);
			if (fieldWidthIdx == 0) {
				return i;
			}
			i += Integer.toString(fieldWidthIdx).length() + 1;
			// i should be at $
			formatArgumentMap.put(fieldWidthIdx, new FormatArgument(null, "d"));
		}
		else {
			i = skipIntegers(formatString, i);
			if (i == -1) {
				return i;
			}
		}
		data.setFieldWidthComplete(true);
		return i;

	}

	private List<FormatArgument> convertMapToList(Map<Integer, FormatArgument> formatArgumentMap) {
		List<FormatArgument> formatArgumentList = new ArrayList<>();
		for (int i = 1; i <= formatArgumentMap.size(); i++) {
			FormatArgument formatArgument = formatArgumentMap.get(i);
			if (formatArgument == null) {
				return null;
			}
			formatArgumentList.add(formatArgument);
		}
		return formatArgumentList;
	}

	/**
	 * In a format string with format argument parameters, retrieve that parameter.
	 * In other words, in the following cases: "%n$" and "*n$", return n where n is
	 * the index of the referred argument. n cannot be less than 1; return 0 if
	 * there's a problem.
	 * 
	 * @param formatString format String
	 * @param i      index within formatStr
	 * @return formar argument parameter
	 */
	private int locateParameterIndex(String formatString, int i) {

		char c = formatString.charAt(i);
		if (c == '%' || c == '*') {
			++i;
			c = formatString.charAt(i);
		}
		else {
			return 0;
		}
		String paramIndexString = "";
		while (Character.isDigit(c)) {
			paramIndexString += Character.toString(c);
			++i;
			c = formatString.charAt(i);
		}
		return c != '$' || paramIndexString.length() == 0 || Integer.parseInt(paramIndexString) == 0
				? 0
				: Integer.parseInt(paramIndexString);
	}

	/**
	 * Skips a series of flags within a format String. returns the index of the
	 * format string at the last digit before another non-digit character
	 * 
	 * @param formatString format String
	 * @param i      index into formatStr
	 * @return new index into formatStr
	 */
	private int skipFlags(String formatString, int i) {
		for (; isFlag(formatString.charAt(i)); i++) {
			// Iterate through chars until all flags are skipped
		}
		return i - 1;
	}

	/**
	 * Skips a series of numbers (field width or precision) within a format String.
	 * returns the index of the format String at the last digit before another
	 * non-digit character
	 * 
	 * @param formatString format String
	 * @param i      index into formatStr
	 * @return new index into formatString
	 */
	private int skipIntegers(String formatString, int i) {
		char c = formatString.charAt(i);
		if (!Character.isDigit(c)) {
			if (isLengthModifier(c) || isConversionSpecifier(c)) {
				return i - 1;
			}
			return -1;
		}
		for (; Character.isDigit(formatString.charAt(i)); i++) {
			// Skip chars until a non-integer is found
		}
		return i - 1;
	}

	// If there are two consecutive '%' signs, do not evaluate the data types
	private boolean emitPercent(String formatString, int i) {
		if (formatString.charAt(i) == '%' && i + 1 < formatString.length() &&
			formatString.charAt(i + 1) == '%') {
			return true;
		}
		return false;
	}

	public DataType[] convertToOutputDataTypes(List<FormatArgument> formatArguments) {
		if (formatArguments == null) {
			return null;
		}
		List<DataType> dataTypeList = formatArguments.stream().map(argument -> {
			String conversionSpecifier = argument.getConversionSpecifier();
			DataType dt = convertPairToDataType(argument.getLengthModifier(),
				conversionSpecifier.equals("*") ? "d" : conversionSpecifier);
			return dt;
		}).collect(Collectors.toList());
		return dataTypeList.contains(null) ? null
				: dataTypeList.toArray(DataType[]::new);
	}

	public DataType[] convertToInputDataTypes(List<FormatArgument> formatArguments) {
		if (formatArguments == null) {
			return null;
		}

		List<DataType> dataTypesList = new ArrayList<>();
		for (int i = 0; i < formatArguments.size(); i++) {
			FormatArgument argument = formatArguments.get(i);
			// * means to skip
			if (argument.getConversionSpecifier().equals("*")) {
				if (formatArguments.get(i + 1).getConversionSpecifier().equals("*")) {
					return null;
				}
				++i;
				continue;
			}
			DataType dt = convertPairToDataType(argument.getLengthModifier(),
				argument.getConversionSpecifier());
			if (dt == null) {
				return null;
			}
			if (!(dt instanceof PointerDataType) ||
				isVoidPointer(argument.getConversionSpecifier())) {
				dataTypesList.add(dataTypeManager.getPointer(dt));
			}
			else {
				dataTypesList.add(dt);
			}
		}
		return dataTypesList.stream().toArray(size -> new DataType[size]);
	}

	private boolean verifyConversionPair(String lengthModifier, String conversionSpecifier) {
		if (lengthModifier == null || lengthModifier.equals("l")) {
			return true;
		}
		if ((lengthModifier.equals("L") && isDouble(conversionSpecifier)) ||
			(!lengthModifier.equals("L") &&
				(isInteger(conversionSpecifier) || isIntegerPointer(conversionSpecifier)))) {
			return true;
		}
		return false;
	}

	private DataType convertPairToDataType(String lengthModifier, String conversionSpecifier) {

		if (lengthModifier == null || conversionSpecifier.equals("c") ||
			conversionSpecifier.equals("s") ||
			conversionSpecifier.equals("C") ||
			conversionSpecifier.equals("S")) {
			return conversionSpecifierToDataType(conversionSpecifier);
		}
		switch (lengthModifier) {
			case "h":
				return shortLengthModification(conversionSpecifier);
			case "hh":
				return charLengthModification(conversionSpecifier);
			case "l":
				return longLengthModification(conversionSpecifier);
			case "ll":
			case "q":
				return longLongLengthModification(conversionSpecifier);
			case "j":
				return intmax_t_LengthModification(conversionSpecifier);
			case "z":
				return size_t_LengthModification(conversionSpecifier);
			case "t":
				return ptrdiff_t_LengthModification(conversionSpecifier);
			case "L":
				return longDoubleLengthModification(conversionSpecifier);
			default:
				return null;
		}
	}

	private DataType conversionSpecifierToDataType(String conversionSpecifier) {
		switch (conversionSpecifier.charAt(0)) {
			case 'd':
			case 'i':
				return new IntegerDataType(dataTypeManager);
			case 'o':
			case 'u':
			case 'x':
			case 'X':
				return new UnsignedIntegerDataType(dataTypeManager);
			case 'p':
				return dataTypeManager.getPointer(DataType.VOID);
			case 's':
				return dataTypeManager.getPointer(new CharDataType(dataTypeManager));
			case 'n':
				return dataTypeManager.getPointer(new IntegerDataType(dataTypeManager));
			case 'c':
				return new UnsignedCharDataType(dataTypeManager);
			case 'a':
			case 'A':
			case 'g':
			case 'G':
			case 'e':
			case 'E':
			case 'f':
				return new DoubleDataType(dataTypeManager);
			case 'S':
			case 'C':
				return dataTypeManager.getPointer(new WideCharDataType(dataTypeManager));
			default:
				return null;
		}
	}

	private DataType longLengthModification(String conversionSpecifier) {
		if (isIntegerPointer(conversionSpecifier)) {
			return dataTypeManager.getPointer(new LongDataType(dataTypeManager));
		}
		if (conversionSpecifier.contentEquals("s") || conversionSpecifier.contentEquals("c")) {
			return dataTypeManager.getPointer(new WideCharDataType(dataTypeManager));
		}
		return isSignedInteger(conversionSpecifier) ? new LongDataType(dataTypeManager)
				: new UnsignedLongDataType(dataTypeManager);
	}

	private DataType longLongLengthModification(String conversionSpecifier) {
		if (isIntegerPointer(conversionSpecifier)) {
			return dataTypeManager.getPointer(new LongLongDataType(dataTypeManager));
		}
		return isSignedInteger(conversionSpecifier)
				? new LongLongDataType(dataTypeManager)
				: new UnsignedLongLongDataType(dataTypeManager);
	}

	private DataType shortLengthModification(String conversionSpecifier) {
		if (isIntegerPointer(conversionSpecifier)) {
			return dataTypeManager.getPointer(new ShortDataType(dataTypeManager));
		}
		return isSignedInteger(conversionSpecifier)
				? new ShortDataType(dataTypeManager)
				: new UnsignedShortDataType(dataTypeManager);
	}

	private DataType charLengthModification(String conversionSpecifier) {
		if (isIntegerPointer(conversionSpecifier)) {
			return dataTypeManager.getPointer(new CharDataType(dataTypeManager));
		}
		return isSignedInteger(conversionSpecifier) ? new CharDataType(dataTypeManager)
				: new UnsignedCharDataType(dataTypeManager);
	}

	private TypeDef lookupTypeDef(String name) {
		List<DataType> typeList = new ArrayList<>();
		dataTypeManager.findDataTypes(name, typeList);
		for (DataType dt : typeList) {
			if (!(dt instanceof TypeDef)) {
				continue;
			}
			TypeDef td = (TypeDef) dt;
			if (td.getBaseDataType() instanceof AbstractIntegerDataType) {
				return td;
			}
		}
		return null;
	}

	private TypeDef getIntMaxT() {
		if (intmax_t != null) {
			return intmax_t;
		}
		intmax_t = lookupTypeDef(INTMAX_T_NAME);
		if (intmax_t == null) {
			intmax_t = new TypedefDataType(INTMAX_T_NAME, new LongLongDataType(dataTypeManager));
			Msg.warn(this, INTMAX_T_NAME + " not defined.  Generated as `" + intmax_t + "'");
		}
		return intmax_t;
	}

	private TypeDef getUIntMaxT() {
		if (uintmax_t != null) {
			return uintmax_t;
		}
		uintmax_t = lookupTypeDef(UINTMAX_T_NAME);
		if (uintmax_t == null) {
			uintmax_t =
				new TypedefDataType(UINTMAX_T_NAME, new UnsignedLongLongDataType(dataTypeManager));
			Msg.warn(this, UINTMAX_T_NAME + " not defined.  Generated as `" + uintmax_t + "'");
		}
		return uintmax_t;
	}

	private AbstractIntegerDataType getIntegralPointerType(boolean signed) {
		DataOrganization dataOrganization = dataTypeManager.getDataOrganization();
		int size = dataOrganization.getPointerSize();
		if (size < dataOrganization.getLongSize() && size >= dataOrganization.getIntegerSize()) {
			return signed ? new IntegerDataType(dataTypeManager)
					: new UnsignedIntegerDataType(dataTypeManager);
		}
		return signed ? new LongDataType(dataTypeManager)
				: new UnsignedLongDataType(dataTypeManager);
	}

	private TypeDef getSizeT() {
		if (size_t != null) {
			return size_t;
		}
		size_t = lookupTypeDef(SIZE_T_NAME);
		if (size_t == null) {
			size_t = new TypedefDataType(SIZE_T_NAME, getIntegralPointerType(false));
			Msg.warn(this, SIZE_T_NAME + " not defined.  Generated as `" + size_t + "'");
		}
		return size_t;
	}

	private TypeDef getPtrDiffT() {
		if (ptrdiff_t != null) {
			return ptrdiff_t;
		}
		ptrdiff_t = lookupTypeDef(PTRDIFF_T_NAME);
		if (ptrdiff_t == null) {
			ptrdiff_t = new TypedefDataType(PTRDIFF_T_NAME, getIntegralPointerType(true));
			Msg.warn(this, PTRDIFF_T_NAME + " not defined.  Generated as `" + ptrdiff_t + "'");
		}
		return ptrdiff_t;
	}

	private DataType intmax_t_LengthModification(String conversionSpecifier) {
		TypeDef intType = isUnsignedInteger(conversionSpecifier) ? getUIntMaxT() : getIntMaxT();
		return isIntegerPointer(conversionSpecifier)
				? dataTypeManager.getPointer(intType)
				: intType;
	}

	private DataType size_t_LengthModification(String conversionSpecifier) {
		TypeDef sizeType = getSizeT();
		return isIntegerPointer(conversionSpecifier)
				? dataTypeManager.getPointer(sizeType)
				: sizeType;
	}

	private DataType ptrdiff_t_LengthModification(String conversionSpecifier) {
		TypeDef type = isUnsignedInteger(conversionSpecifier) ? getSizeT() : getPtrDiffT();
		return isIntegerPointer(conversionSpecifier)
				? dataTypeManager.getPointer(type)
				: type;
	}

	private DataType longDoubleLengthModification(String conversionSpecifier) {
		return new LongDoubleDataType(dataTypeManager);
	}

	private boolean isInteger(String conversionSpecifier) {
		return isUnsignedInteger(conversionSpecifier) || isSignedInteger(conversionSpecifier);
	}

	private boolean isDouble(String conversionSpecifier) {
		char c = conversionSpecifier.charAt(0);
		String doubleConversionSpecifierSet = "aAeEfFgG";
		return doubleConversionSpecifierSet.indexOf(c) != -1;
	}

	private boolean isUnsignedInteger(String conversionSpecifier) {
		char c = conversionSpecifier.charAt(0);
		String unsignedIntSpecifierSet = "ouxX";
		return unsignedIntSpecifierSet.indexOf(c) != -1;
	}

	private boolean isSignedInteger(String conversionSpecifier) {
		char c = conversionSpecifier.charAt(0);
		String signedIntSpecifierSet = "di";
		return signedIntSpecifierSet.indexOf(c) != -1;
	}

	private boolean isIntegerPointer(String conversionSpecifier) {
		char c = conversionSpecifier.charAt(0);
		String pointerSpecifierSet = "n";
		return pointerSpecifierSet.indexOf(c) != -1;
	}

	private boolean isVoidPointer(String conversionSpecifier) {
		char c = conversionSpecifier.charAt(0);
		String voidPointerSpecifierSet = "p";
		return voidPointerSpecifierSet.indexOf(c) != -1;
	}

	private boolean isFlag(char c) {
		String flagSpecifierSet = "0+ -#'";
		return flagSpecifierSet.indexOf(c) != -1;
	}

	private String extendLengthModifier(String lengthModifier, char nextChar) {
		if ((lengthModifier.equals("h") && nextChar == 'h') ||
			(lengthModifier.equals("l") && nextChar == 'l')) {
			return lengthModifier + Character.toString(nextChar);
		}
		return null;
	}

	private boolean isConversionSpecifier(char c) {
		return detectConversionSpecifier(c) != null;
	}

	private boolean isLengthModifier(char c) {
		return detectLengthModifier(c) != null;
	}

	private String detectLengthModifier(char c) {
		String lengthModifierSet = "hljztLq";
		return lengthModifierSet.indexOf(c) != -1 ? Character.toString(c) : null;
	}

	private String detectConversionSpecifier(char c) {
		String conversionSpecifierSet = "diuofeaFEApcsxXgGnCS";
		return conversionSpecifierSet.indexOf(c) != -1 ? Character.toString(c) : null;
	}

	public int skipToNextWhitespace(String formatStr, int i) {
		char c = formatStr.charAt(i);
		while (c != ' ') {
			++i;
			c = formatStr.charAt(i);
		}
		return i;
	}

	private class FormatParsingData {

		private String conversionSpecifier = null;
		private String lengthModifier = null;
		private boolean fieldWidthComplete = false;
		private boolean precisionComplete = false;
		private boolean inConversion = false;
		private int parameterIndex = 0;

		private void setParameterIndex(int parameterIndex) {
			this.parameterIndex = parameterIndex;
		}

		private int getParameterIndex() {
			return this.parameterIndex;
		}

		private void setConversionSpecifier(String conversionSpecifier) {
			this.conversionSpecifier = conversionSpecifier;
		}

		private String getConversionSpecifier() {
			return this.conversionSpecifier;
		}

		private void setLengthModifier(String lengthModifier) {
			this.lengthModifier = lengthModifier;
		}

		private String getLengthModifier() {
			return this.lengthModifier;
		}

		private boolean isFieldWidthComplete() {
			return this.fieldWidthComplete;
		}

		private void setFieldWidthComplete(boolean fieldWidthComplete) {
			this.fieldWidthComplete = fieldWidthComplete;
		}

		private boolean isPrecisionComplete() {
			return this.precisionComplete;
		}

		private void setPrecisionComplete(boolean precisionComplete) {
			this.precisionComplete = precisionComplete;
		}

		private void setInConversion(boolean inConversion) {
			this.inConversion = inConversion;
		}

		private boolean isInConversion() {
			return this.inConversion;
		}

		private void clearData() {
			this.precisionComplete = false;
			this.fieldWidthComplete = false;
			this.lengthModifier = null;
			this.conversionSpecifier = null;
		}
	}

}
