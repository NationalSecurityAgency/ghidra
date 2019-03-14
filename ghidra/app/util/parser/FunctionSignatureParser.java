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
package ghidra.app.util.parser;

import java.util.*;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * Class for parsing function signatures. This class attempts to be much more flexible than
 * a full parser that requires correct C or C++ syntax.  To achieve this, it scans the original
 * function signature (if present) for names that would cause parse problems (parens, commas, and
 * spaces).  If it finds any problem names, it looks for those strings in the text to be parsed and
 * if it finds them, it replaces them with substitutes that parse easily.  Then, after parsing, those
 * replacement strings are then restored to their original values.
 * <P>
 * Some examples of valid c++ that would fail due to the current limitations:
 * <P>
 * void foo(myclass<int, float> x) - fails due to comma in x's data type name
 * int operator()(int x) - fails due to parens in function name
 * unsigned int bar(float y) - fails due to space in return type name
 * <P>
 * Note: you can edit signatures that already have these features as long as your modifications
 * don't affect the pieces containing parens, commas or spaces in their name.
 */
public class FunctionSignatureParser {
	private static final String REPLACEMENT_DT_NAME = "__REPLACE_DT_NAME__";
	private static final String REPLACE_NAME = "__REPLACE_NAME__";
	private DataTypeParser dataTypeParser;
	private Map<String, DataType> dtMap = new HashMap<>();
	private Map<String, String> nameMap = new HashMap<>();

	/**
	 * Constructs a SignatureParser for a program.
	 *
	 * @param program the program whose datatype manager is used to resolve datatype names.
	 * @param service the DataTypeManagerService to use for resolving datatypes that can't be
	 * found in the given program. Can be null to utilize program based types only.
	 */
	public FunctionSignatureParser(Program program, DataTypeManagerService service) {
		if (service == null) {
			if (program == null) {
				throw new IllegalArgumentException("program or service provider required");
			}
			DataTypeManager dataTypeManager = program.getDataTypeManager();
			dataTypeParser = new DataTypeParser(dataTypeManager, dataTypeManager, null,
				AllowedDataTypes.FIXED_LENGTH);
		}
		else {
			dataTypeParser = new DataTypeParser(service, AllowedDataTypes.FIXED_LENGTH);
		}
	}

	/**
	 * Parse the given function signature text into a FunctionDefinitionDataType.
	 *
	 * @param originalSignature the function signature before editing.  This may be null
	 * if the user is entering a new signature instead of editing an existing one.
	 * @param signatureText the text to be parsed into a function signature.
	 * @return the FunctionDefinitionDataType resulting from parsing.
	 * @throws ParseException if the text could not be parsed.
	 */
	public FunctionDefinitionDataType parse(FunctionSignature originalSignature,
			String signatureText) throws ParseException {
		dtMap.clear();
		nameMap.clear();

		if (originalSignature != null) {
			initDataTypeMap(originalSignature);
			signatureText = cleanUpSignatureText(signatureText, originalSignature);
		}

		String functionName = extractFunctionName(signatureText);
		FunctionDefinitionDataType function = new FunctionDefinitionDataType(functionName);

		function.setReturnType(extractReturnType(signatureText));
		function.setArguments(extractArguments(signatureText));
		function.setVarArgs(hasVarArgs(signatureText));

		return function;
	}

	private void initDataTypeMap(FunctionSignature signature) {
		cacheDataType(signature.getReturnType());
		for (ParameterDefinition p : signature.getArguments()) {
			cacheDataType(p.getDataType());
		}
	}

	private void cacheDataType(DataType dataType) {
		if (dataType == null || (dataType instanceof Dynamic) ||
			(dataType instanceof FactoryDataType)) {
			return;
		}
		DataType baseType = null;
		if (dataType instanceof Pointer) {
			baseType = ((Pointer) dataType).getDataType();
		}
		else if (dataType instanceof Array) {
			baseType = ((Array) dataType).getDataType();
		}
		else if (dataType instanceof TypeDef) {
			baseType = ((TypeDef) dataType).getDataType();
		}
		dtMap.put(dataType.getName(), dataType);
		cacheDataType(baseType);
	}

	private static DataTypeManagerService getDataTypeManagerService(ServiceProvider provider) {
		if (provider != null) {
			return provider.getService(DataTypeManagerService.class);
		}
		return null;
	}

	private boolean hasVarArgs(String newSignatureText) {
		int startIndex = newSignatureText.lastIndexOf(',');
		int endIndex = newSignatureText.indexOf(')');
		if (startIndex < 0 || endIndex < 0 || startIndex >= endIndex) {
			return false;
		}
		String lastArg = newSignatureText.substring(startIndex + 1, endIndex).trim();
		return "...".equals(lastArg);
	}

	private ParameterDefinition[] extractArguments(String newSignatureText) throws ParseException {
		int startIndex = newSignatureText.indexOf('(');
		int endIndex = newSignatureText.indexOf(')');
		if (startIndex < 0 || endIndex < 0 || startIndex >= endIndex) {
			throw new ParseException("Can't parse function arguments");
		}
		String trailingText = newSignatureText.substring(endIndex + 1);
		if (trailingText.trim().length() > 0) {
			throw new ParseException(
				"Unexpected trailing text at end of function: " + trailingText);
		}

		String argString = newSignatureText.substring(startIndex + 1, endIndex).trim();
		if (argString.length() == 0) {
			return new ParameterDefinition[0];
		}
		if ("void".equalsIgnoreCase(argString)) {
			return new ParameterDefinition[0];
		}

		List<ParameterDefinition> parameterList = new ArrayList<>();
		String[] split = argString.split(",");

		for (String arg : split) {
			addParameter(parameterList, arg.trim());
		}
		return parameterList.toArray(new ParameterDefinition[parameterList.size()]);
	}

	private void addParameter(List<ParameterDefinition> parameterList, String arg)
			throws ParseException {
		if ("...".equals(arg)) {
			return;
		}
		if (arg.length() == 0) {
			throw new ParseException("Missing parameter");
		}

		// Attempt to resolve parameter assuming only a datatype is specified
		DataType dt = resolveDataType(arg);
		if (dt != null) {
			parameterList.add(new ParameterDefinitionImpl(null, dt, null));
			return;
		}

		// attempt to separate trailing parameter name from datatype and reparse
		int spaceIndex = arg.lastIndexOf(' ');
		if (spaceIndex < 0) {
			throw new ParseException("Can't resolve datatype: " + dt);
		}
		int starIndex = arg.lastIndexOf('*');
		int nameIndex = Math.max(spaceIndex, starIndex) + 1;

		String name = resolveName(arg.substring(nameIndex).trim());
		String dtName = arg.substring(0, nameIndex).trim();
		dt = resolveDataType(dtName);
		if (dt == null) {
			throw new ParseException("Can't resolve datatype: " + dtName);
		}
		parameterList.add(new ParameterDefinitionImpl(name, dt, null));
	}

	String cleanUpSignatureText(String text, FunctionSignature signature) {
		DataType returnType = signature.getReturnType();
		text = replaceDataTypeIfNeeded(text, returnType, REPLACEMENT_DT_NAME);
		text = replaceNameIfNeeded(text, signature.getName(), REPLACE_NAME);

		ParameterDefinition[] arguments = signature.getArguments();
		for (ParameterDefinition argument : arguments) {
			text = replaceDataTypeIfNeeded(text, argument.getDataType(),
				REPLACEMENT_DT_NAME + argument.getOrdinal());
			text =
				replaceNameIfNeeded(text, argument.getName(), REPLACE_NAME + argument.getOrdinal());
		}
		return text;
	}

	private String replaceDataTypeIfNeeded(String text, DataType dataType, String replacementName) {
		String displayName = dataType.getDisplayName();
		if (canParse(displayName)) {
			return text;
		}

		dtMap.put(replacementName, dataType);

		return substitute(text, displayName, replacementName);
	}

	private String replaceNameIfNeeded(String text, String name, String replacementName) {
		if (canParse(name)) {
			return text;
		}
		nameMap.put(replacementName, name);
		return substitute(text, name, replacementName);
	}

	DataType extractReturnType(String signatureText) throws ParseException {
		int parenIndex = signatureText.indexOf('(');
		if (parenIndex < 0) {
			throw new ParseException("Can't find return type");
		}
		String[] split = StringUtils.split(signatureText.substring(0, parenIndex));
		if (split.length < 2) {
			throw new ParseException("Can't find return type");
		}
		String returnTypeName = StringUtils.join(split, " ", 0, split.length - 1);

		DataType dt = resolveDataType(returnTypeName);
		if (dt == null) {
			throw new ParseException("Can't resolve return type: " + returnTypeName);
		}
		return dt;
	}

	private DataType resolveDataType(String dataTypeName) {
		if (dtMap.containsKey(dataTypeName)) {
			return dtMap.get(dataTypeName);
		}

		DataType dataType = null;
		try {
			dataType = dataTypeParser.parse(dataTypeName);
		}
		catch (InvalidDataTypeException e) {
			// ignore
		}
		return dataType;
	}

	String extractFunctionName(String signatureText) throws ParseException {
		int parenIndex = signatureText.indexOf('(');
		if (parenIndex < 0) {
			throw new ParseException("Can't find function name");
		}
		String[] split = StringUtils.split(signatureText.substring(0, parenIndex));
		if (split.length < 2) {
			throw new ParseException("Can't find function name");
		}

		String name = split[split.length - 1];
		return resolveName(name);
	}

	private String resolveName(String name) throws ParseException {
		if (nameMap.containsKey(name)) {
			return nameMap.get(name);
		}
		if (!canParse(name)) {
			throw new ParseException("Can't parse name: " + name);
		}
		return name;
	}

	String substitute(String text, String searchString, String replacementString) {
		return text.replaceFirst(Pattern.quote(searchString), replacementString);
	}

	private boolean canParse(String text) {
		return !StringUtils.containsAny(text, "(), ");
	}

}
