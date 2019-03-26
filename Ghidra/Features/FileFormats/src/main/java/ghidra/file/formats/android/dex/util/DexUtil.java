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
package ghidra.file.formats.android.dex.util;

import java.util.StringTokenizer;

import ghidra.file.formats.android.dex.format.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public final class DexUtil {

	public final static long METHOD_ADDRESS = 0x50000000;

	public final static long LOOKUP_ADDRESS = 0xE0000000;

	public final static long MAX_METHOD_LENGTH = (long) Math.pow(2, 16) * 4;

	public final static String CLASSDEF_NAME = "__classdef__";

	public final static String CATEGORY_PATH = "classes/";

	public final static String HANDLE_PATH = "/handles/";

	public static Address toLookupAddress(Program program, int methodIndex) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		return defaultAddressSpace.getAddress(DexUtil.LOOKUP_ADDRESS + (methodIndex * 4));
	}

	public static Namespace getOrCreateNameSpace(Program program, String name) {
		SymbolTable symbolTable = program.getSymbolTable();
		Namespace parent = program.getGlobalNamespace();

		Namespace namespace = symbolTable.getNamespace(name, parent);
		if (namespace != null) {
			return namespace;
		}
		try {
			return symbolTable.createNameSpace(parent, name, SourceType.ANALYSIS);
		}
		catch (Exception e) {
			return program.getGlobalNamespace();
		}
	}

	public static Namespace createNameSpaceFromMangledClassName(Program program, String className)
			throws InvalidInputException {
		Namespace namespace = program.getGlobalNamespace();
		return createNameSpaceFromMangledClassName(program, namespace, className);
	}

	public static Namespace createNameSpaceFromMangledClassName(Program program,
			Namespace parentNamespace, String className) throws InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		if (className.startsWith("L") && className.endsWith(";")) {
			String str = className.substring(1, className.length() - 1);
			StringTokenizer tokenizer = new StringTokenizer(str, "/");
			while (tokenizer.hasMoreTokens()) {
				String token = tokenizer.nextToken();

				Namespace ns = symbolTable.getNamespace(token, parentNamespace);
				if (ns != null) {
					parentNamespace = ns;
					continue;
				}

				try {
					if (tokenizer.hasMoreElements()) { // package name
						parentNamespace = symbolTable.createNameSpace(parentNamespace, token,
							SourceType.ANALYSIS);
					}
					else { // last token should be the class name
						parentNamespace =
							symbolTable.createClass(parentNamespace, token, SourceType.ANALYSIS);
					}
				}
				catch (DuplicateNameException e) {
					// Should never reach here because we already checked for the symbol name
					return null;
				}
			}
		}
		return parentNamespace;
	}

	public static String convertTypeIndexToString(DexHeader header, short typeIndex) {
		return convertTypeIndexToString(header, typeIndex & 0xffff);
	}

	public static String convertTypeIndexToString(DexHeader header, int typeIndex) {
		if (typeIndex == -1) {//java.lang.Object, no super class
			return "<none>";
		}
		TypeIDItem typeItem = header.getTypes().get(typeIndex);
		return convertToString(header, typeItem.getDescriptorIndex());
	}

	public static String convertToString(DexHeader header, int stringIndex) {
		StringIDItem stringItem = header.getStrings().get(stringIndex);
		return stringItem.getStringDataItem().getString();
	}

	public static String convertPrototypeIndexToString(DexHeader header, short prototypeIndex) {
		PrototypesIDItem prototype = header.getPrototypes().get(prototypeIndex & 0xffff);
		StringBuilder builder = new StringBuilder();
		builder.append(convertTypeIndexToString(header, prototype.getReturnTypeIndex()));
		builder.append("( ");
		TypeList parameters = prototype.getParameters();
		if (parameters != null) {
			for (TypeItem parameter : parameters.getItems()) {
				builder.append(convertTypeIndexToString(header, parameter.getType()));
				builder.append("\n\t");
			}
		}
		builder.append(" )");
		return builder.toString();
	}

	public static String[] convertClassStringToPathArray(String prefix, String classString) {
		int len = classString.length();
		if (len == 0) {
			return null;
		}
		if (classString.charAt(0) != 'L') {
			return null;
		}
		if (classString.charAt(len - 1) != ';') {
			return null;
		}
		return (prefix + classString.substring(1, len - 1)).split("/");
	}

	public static DataType toDataType(DataTypeManager dtm, String dataTypeString) {
		if (dataTypeString.length() == 0) {
			return null;
		}
		switch (dataTypeString.charAt(0)) {
			case 'B':
				return SignedByteDataType.dataType;
			case 'C':
				return CharDataType.dataType;
			case 'D':
				return DoubleDataType.dataType;
			case 'F':
				return FloatDataType.dataType;
			case 'I':
				return IntegerDataType.dataType;
			case 'J':
				return new LongDataType(dtm);
			case 'S':
				return ShortDataType.dataType;
			case 'Z':
				return BooleanDataType.dataType;
			case 'V':
				return VoidDataType.dataType;
			case 'L':
				String[] path = convertClassStringToPathArray(CATEGORY_PATH, dataTypeString);
				StringBuilder builder = new StringBuilder();
				for (int i = 0; i < path.length - 1; ++i) {
					builder.append(CategoryPath.DELIMITER_CHAR).append(path[i]);
				}
				CategoryPath catPath = new CategoryPath(builder.toString());
				DataType exist = dtm.getDataType(catPath, path[path.length - 1]);
				if (exist == null) {
					exist = Undefined4DataType.dataType;
				}
				return new PointerDataType(exist, dtm);
			case '[':
				DataType subDataType = toDataType(dtm, dataTypeString.substring(1));
				return new PointerDataType(subDataType, dtm);
			default:
				return null;
		}
	}
}
