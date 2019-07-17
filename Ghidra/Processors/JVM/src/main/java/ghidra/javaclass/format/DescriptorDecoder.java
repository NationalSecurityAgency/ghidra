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
package ghidra.javaclass.format;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.pcodeInject.*;
import ghidra.javaclass.format.constantpool.*;
import ghidra.program.model.data.*;

/**
 * 
 * This is a utility class containing methods to parse information of out of method 
 * and field descriptors.
 *
 */

public class DescriptorDecoder {

	public final static byte BASE_TYPE_BYTE = 'B';
	public final static byte BASE_TYPE_CHAR = 'C';
	public final static byte BASE_TYPE_SHORT = 'S';
	public final static byte BASE_TYPE_INT = 'I';
	public final static byte BASE_TYPE_LONG = 'J';
	public final static byte BASE_TYPE_FLOAT = 'F';
	public final static byte BASE_TYPE_DOUBLE = 'D';
	public final static byte BASE_TYPE_BOOLEAN = 'Z';
	public final static byte BASE_TYPE_STRING = 's';
	public final static byte BASE_TYPE_VOID = 'V';
	public final static byte BASE_TYPE_CLASS = 'c';
	public final static byte BASE_TYPE_ARRAY = '[';
	public final static byte BASE_TYPE_REFERENCE = 'L';
	public final static byte BASE_TYPE_ENUM = 'e';
	public final static byte BASE_TYPE_ANNOTATION = '@';

	//private constructor to enforce noninstantiability
	private DescriptorDecoder() {
		throw new AssertionError();
	}

	/**
	 * Calculates the stack purge associated with a given method descriptor. Each parameter of computational category
	 * one contributes 4 to the stack purge, and each parameter of computational category 2 contributes 8.
	 * @param methodDescriptor
	 * @return
	 */
	public static int getStackPurge(String methodDescriptor) {
		int stackPurge = 0;
		List<JavaComputationalCategory> categories = getParameterCategories(methodDescriptor);
		for (JavaComputationalCategory cat : categories) {
			switch (cat) {
				case CAT_1:
					stackPurge += PcodeInjectLibraryJava.REFERENCE_SIZE;
					break;
				case CAT_2:
					stackPurge += PcodeInjectLibraryJava.REFERENCE_SIZE * 2;
					break;
				default:
					throw new IllegalArgumentException("Bad category!");
			}
		}
		return stackPurge;
	}

	/**
	 * Returns the computational category of the return type of a method descriptor.
	 * @param methodDescriptor
	 * @return
	 */
	public static JavaComputationalCategory getReturnCategoryOfMethodDescriptor(
			String methodDescriptor) {
		int closeParenIndex = methodDescriptor.indexOf(")");
		if (closeParenIndex == -1) {
			throw new IllegalArgumentException("Invalid method descriptor: " + methodDescriptor);
		}
		String returnDescriptor =
			methodDescriptor.substring(closeParenIndex + 1, methodDescriptor.length());
		return DescriptorDecoder.getComputationalCategoryOfDescriptor(returnDescriptor);
	}

	/**
	 * Given a method descriptor, returns the data type of the return value of the corresponding
	 * method
	 * @param methodDescriptor descriptor of method
	 * @param dtManager data type manger for containing program
	 * @return data type of return value of method
	 */
	public static DataType getReturnTypeOfMethodDescriptor(String methodDescriptor,
			DataTypeManager dtManager) {
		int closeParenIndex = methodDescriptor.indexOf(")");
		if (closeParenIndex == -1) {
			throw new IllegalArgumentException("Invalid method descriptor: " + methodDescriptor);
		}
		String returnDescriptor =
			methodDescriptor.substring(closeParenIndex + 1, methodDescriptor.length());
		if (returnDescriptor.startsWith("[")) {
			return getPointerType(returnDescriptor, dtManager);
		}
		return DescriptorDecoder.getDataTypeOfDescriptor(returnDescriptor, dtManager);
	}

	/**
	 * Returns the computational category of a given parameter or field descriptor
	 * @param descriptor
	 * @return
	 */
	public static JavaComputationalCategory getComputationalCategoryOfDescriptor(
			String descriptor) {
		//all references to objects start with "L"
		//all references to arrays start with "["
		//all other descriptors are just one letter. 
		switch (descriptor.charAt(0)) {
			case BASE_TYPE_BYTE:  //signed byte
			case BASE_TYPE_CHAR:  //char
			case BASE_TYPE_FLOAT:  //float
			case BASE_TYPE_INT:  //int
			case BASE_TYPE_REFERENCE:  //object reference
			case BASE_TYPE_SHORT:  //signed short
			case BASE_TYPE_BOOLEAN:  //boolean
			case BASE_TYPE_ARRAY:  //array dimension
				return JavaComputationalCategory.CAT_1;
			case BASE_TYPE_DOUBLE:  //double
			case BASE_TYPE_LONG:  //long
				return JavaComputationalCategory.CAT_2;
			case BASE_TYPE_VOID:  //void (only for return types)
				return JavaComputationalCategory.VOID;
			default:
				throw new IllegalArgumentException("Invalid computational category: " + descriptor);
		}
	}

	/**
	 * Returns an ordered list of the type names corresponding to the parameters and return of a method.
	 * @param methodDescriptor
	 * @return
	 */
	public static List<String> getTypeNameList(String methodDescriptor, boolean fullyQualifiedName,
			boolean replaceSlash) {
		ArrayList<String> typeNames = new ArrayList<>();
		int closeParenIndex = methodDescriptor.indexOf(")");
		String argString = methodDescriptor.substring(1, closeParenIndex);
		String currentParamTypeName;

		int currentPosition = 0;
		int len = argString.length();
		while (currentPosition < len) {
			String currentParam = argString.substring(currentPosition, currentPosition + 1);
			if (currentParam.equals("[")) {
				int initialBracket = currentPosition;
				while (argString.charAt(currentPosition) == '[') {
					currentPosition++;
				}
				//advance past the base type of the array
				if (argString.charAt(currentPosition) == 'L') {
					int semiColonIndex = argString.indexOf(";", currentPosition);
					currentPosition = semiColonIndex + 1;
				}
				else {
					currentPosition++;
				}
				currentParamTypeName =
					getTypeNameFromDescriptor(argString.substring(initialBracket, currentPosition),
						fullyQualifiedName, replaceSlash);
				typeNames.add(currentParamTypeName);
				continue;
			}
			//advance to next type in argString
			//if it's a reference, it starts with L and ends with a ;
			//otherwise you only need to advance one character
			switch (currentParam) {
				case "L":
					int semiColonIndex = argString.indexOf(";", currentPosition);
					currentParamTypeName = getTypeNameFromDescriptor(
						argString.substring(currentPosition, semiColonIndex + 1),
						fullyQualifiedName, replaceSlash);
					currentPosition = semiColonIndex + 1; //advance past ;
					break;
				default:
					currentParamTypeName =
						getTypeNameFromDescriptor(currentParam, fullyQualifiedName, replaceSlash);
					currentPosition++;
			}
			typeNames.add(currentParamTypeName);

		}

		//now add the the name of the return type
		String returnType =
			methodDescriptor.substring(closeParenIndex + 1, methodDescriptor.length());
		typeNames.add(getTypeNameFromDescriptor(returnType, fullyQualifiedName, replaceSlash));
		return typeNames;
	}

	/**
	 * Returns the type name for a parameter descriptor
	 * @param descriptor
	 * @return
	 */
	public static String getTypeNameFromDescriptor(String descriptor, boolean fullyQualifiedName,
			boolean replaceSlash) {
		if (descriptor.startsWith("L")) {
			//leave off the initial L and the final ;
			String name = descriptor.substring(1, descriptor.length() - 1);
			if (fullyQualifiedName) {
				if (replaceSlash) {
					return name.replace("/", ".");
				}
				return name;
			}
			int lastSlash = name.lastIndexOf("/");
			//lastSlash+1 so the slash is not included in the name
			return name.substring(lastSlash + 1, name.length());
		}
		if (descriptor.startsWith("[")) {
			int dimension = descriptor.lastIndexOf("[") + 1;
			String baseType = getTypeNameFromDescriptor(descriptor.replace("[", ""),
				fullyQualifiedName, replaceSlash);
			StringBuilder sb = new StringBuilder(baseType);
			for (int i = 0; i < dimension; ++i) {
				sb.append("[]");
			}
			return sb.toString();
		}
		switch (descriptor.charAt(0)) {
			case BASE_TYPE_BYTE:  //signed byte
				return "byte";
			case BASE_TYPE_CHAR:  //char
				return "char";
			case BASE_TYPE_FLOAT:  //float
				return "float";
			case BASE_TYPE_INT:  //int
				return "int";
			case BASE_TYPE_SHORT:  //signed short
				return "short";
			case BASE_TYPE_BOOLEAN:  //boolean
				return "boolean";
			case BASE_TYPE_DOUBLE:  //double
				return "double";
			case BASE_TYPE_LONG:  //long
				return "long";
			case BASE_TYPE_VOID:  //void (only for return types)
				return "void";
			default:
				throw new IllegalArgumentException("invalid descriptor: " + descriptor);
		}
	}

	public static DataType getReferenceTypeOfDescriptor(String descriptor,
			DataTypeManager dtManager, boolean includesLandSemi) {
		if (includesLandSemi) {
			descriptor = descriptor.substring(1, descriptor.length() - 1);
		}
		String[] parts = descriptor.split("/");
		StringBuilder sb = new StringBuilder();
		for (String part : parts) {
			sb.append(CategoryPath.DELIMITER_CHAR);
			sb.append(part);
		}
		DataTypePath dataPath = new DataTypePath(sb.toString(), parts[parts.length - 1]);
		DataType referencedType = dtManager.getDataType(dataPath);
		return new PointerDataType(referencedType);
	}

	/**
	 * Returns the datatype that the JVM uses to store a given parameter or field descriptor.
	 * @param descriptor
	 * @return
	 */
	public static DataType getDataTypeOfDescriptor(String descriptor, DataTypeManager dtManager) {
		//all references to objects start with "L"
		//all references to arrays start with "["
		//all other descriptors are just one letter. 
		if (descriptor.startsWith("[")) {
			return getPointerType(descriptor, dtManager);
		}
		switch (descriptor.charAt(0)) {
			case BASE_TYPE_BYTE:
				return SignedByteDataType.dataType;
			case BASE_TYPE_CHAR:
				return CharDataType.dataType;
			case BASE_TYPE_INT:
				return IntegerDataType.dataType;
			case BASE_TYPE_SHORT:
				return ShortDataType.dataType;
			case BASE_TYPE_BOOLEAN:
				return BooleanDataType.dataType;
			case BASE_TYPE_FLOAT:
				return FloatDataType.dataType;
			case BASE_TYPE_REFERENCE:  //object reference		
				return getReferenceTypeOfDescriptor(descriptor, dtManager, true);
			case BASE_TYPE_DOUBLE:
				return DoubleDataType.dataType;
			case BASE_TYPE_LONG:
				return LongDataType.dataType;
			case BASE_TYPE_VOID:  //void (only for return types)
				return DataType.VOID;
			default:
				throw new IllegalArgumentException("Invalid type descriptor: " + descriptor);
		}
	}

	/**
	 * Returns the data type of a pointer to the type represented by descriptor
	 * @param descriptor description of base type
	 * @param dtManager data type manager of program
	 * @return pointer data type
	 */
	public static DataType getPointerType(String descriptor, DataTypeManager dtManager) {
		int lastBracket = descriptor.lastIndexOf("[");
		String baseTypeOfArray = descriptor.substring(lastBracket + 1, lastBracket + 2);
		DataType baseType = null;
		switch (baseTypeOfArray.charAt(0)) {
			case BASE_TYPE_BYTE:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_BYTE, dtManager);
				break;
			case BASE_TYPE_BOOLEAN:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_BOOLEAN, dtManager);
				break;
			case BASE_TYPE_CHAR:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_CHAR, dtManager);
				break;
			case BASE_TYPE_DOUBLE:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_DOUBLE, dtManager);
				break;
			case BASE_TYPE_FLOAT:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_FLOAT, dtManager);
				break;
			case BASE_TYPE_INT:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_INT, dtManager);
				break;
			case BASE_TYPE_LONG:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_LONG, dtManager);
				break;
			case BASE_TYPE_SHORT:
				baseType = ArrayMethods.getArrayBaseType(JavaClassConstants.T_SHORT, dtManager);
				break;
			case BASE_TYPE_REFERENCE:
				return dtManager.getPointer(DWordDataType.dataType);

			default:
				throw new IllegalArgumentException(
					"Invalid array base type category: " + baseTypeOfArray);
		}
		return dtManager.getPointer(baseType);
	}

	/**
	 * Returns a list of JavaComputationalCategory objects corresponding to the 
	 * parameters of a method (read in left-to-right order).
	 * @param methodDescriptor
	 * @return
	 */
	public static List<JavaComputationalCategory> getParameterCategories(String methodDescriptor) {
		ArrayList<JavaComputationalCategory> categories = new ArrayList<>();
		int closeParenIndex = methodDescriptor.indexOf(")");
		String argString = methodDescriptor.substring(1, closeParenIndex);
		int currentPosition = 0;
		int len = argString.length();
		while (currentPosition < len) {
			String currentParam = argString.substring(currentPosition, currentPosition + 1);
			JavaComputationalCategory category =
				DescriptorDecoder.getComputationalCategoryOfDescriptor(currentParam);

			switch (category) {
				case CAT_1:
					categories.add(JavaComputationalCategory.CAT_1);
					break;
				case CAT_2:
					categories.add(JavaComputationalCategory.CAT_2);
					break;
				default:
					throw new IllegalArgumentException("Bad category for param:" + category.name());
			}

			//advance to next type in argString
			//if it's a reference, it starts with L and ends with a ;
			//if it's an array, it has one "[" for each dimension, then the type (which might be a reference)
			//otherwise you only need to advance one character
			switch (currentParam) {
				case "L":
					int semiColonIndex = argString.indexOf(";", currentPosition);
					currentPosition = semiColonIndex + 1; //advance past ;
					break;
				case "[":
					//advance past all the ['s
					while (argString.charAt(currentPosition) == '[') {
						currentPosition++;
					}
					//advance past the base type of the array
					if (argString.charAt(currentPosition) == 'L') {
						semiColonIndex = argString.indexOf(";", currentPosition);
						currentPosition = semiColonIndex + 1;
					}
					else {
						currentPosition++;
					}
					break;
				default:
					currentPosition++;  //getComputationalCategoryOfDescriptor has already validated currentParam
			}

		}
		return categories;
	}

	/**
	 * Returns an ordered list of the JVM data types corresponding to the parameters of a method.
	 * @param methodDescriptor
	 * @return
	 */
	public static List<DataType> getDataTypeList(String methodDescriptor,
			DataTypeManager dtManager) {
		ArrayList<DataType> paramDataTypes = new ArrayList<>();
		int closeParenIndex = methodDescriptor.indexOf(")");
		String argString = methodDescriptor.substring(1, closeParenIndex);
		DataType currentParamType;

		int currentPosition = 0;
		int len = argString.length();
		String currentParam = null;
		while (currentPosition < len) {
			int arrayDimensions = 0;
			//if it's an array, decode the number of dimensions
			while (argString.charAt(currentPosition) == '[') {
				arrayDimensions++;
				currentPosition++;
			}
			switch (argString.charAt(currentPosition)) {
				case BASE_TYPE_BYTE:
				case BASE_TYPE_CHAR:
				case BASE_TYPE_SHORT:
				case BASE_TYPE_INT:
				case BASE_TYPE_LONG:
				case BASE_TYPE_FLOAT:
				case BASE_TYPE_DOUBLE:
				case BASE_TYPE_BOOLEAN:
					currentParam = argString.substring(currentPosition, currentPosition + 1);
					currentPosition++;
					break;
				case BASE_TYPE_REFERENCE:
					int semiColonIndex = argString.indexOf(";", currentPosition);
					currentParam = argString.substring(currentPosition, semiColonIndex + 1);
					currentPosition = semiColonIndex + 1;
					break;
			}
			currentParamType = getDataTypeOfDescriptor(currentParam, dtManager);
			if (arrayDimensions > 0) {
				paramDataTypes.add(dtManager.getPointer(currentParamType));
			}
			else {
				paramDataTypes.add(currentParamType);
			}
		}
		return paramDataTypes;
	}

	/**
	 * Given an invocation type and an element in the constant pool, follows references in the the constant
	 * pool and returns the appropriate method descriptor.
	 * @param offset
	 * @param constantPool
	 * @param type
	 * @return
	 */
	public static String getDescriptorForInvoke(int offset,
			AbstractConstantPoolInfoJava[] constantPool, JavaInvocationType type) {
		String descriptor = null;
		int name_and_type_index = 0;
		switch (type) {
			case INVOKE_DYNAMIC:
				ConstantPoolInvokeDynamicInfo dynamicInfo =
					(ConstantPoolInvokeDynamicInfo) constantPool[offset];
				name_and_type_index = dynamicInfo.getNameAndTypeIndex();
				break;
			case INVOKE_INTERFACE:
				ConstantPoolInterfaceMethodReferenceInfo interfaceInfo =
					(ConstantPoolInterfaceMethodReferenceInfo) constantPool[offset];
				name_and_type_index = interfaceInfo.getNameAndTypeIndex();
				break;
			case INVOKE_STATIC:
				AbstractConstantPoolInfoJava poolElem = constantPool[offset];
				if (poolElem instanceof ConstantPoolInterfaceMethodReferenceInfo) {
					interfaceInfo = (ConstantPoolInterfaceMethodReferenceInfo) constantPool[offset];
					name_and_type_index = interfaceInfo.getNameAndTypeIndex();
					break;
				}
				if (poolElem instanceof ConstantPoolMethodReferenceInfo) {
					ConstantPoolMethodReferenceInfo methodReferenceInfo =
						(ConstantPoolMethodReferenceInfo) constantPool[offset];
					name_and_type_index = methodReferenceInfo.getNameAndTypeIndex();
					break;
				}
				throw new IllegalArgumentException(
					"Unsupported type for invokestatic at constant pool element " + offset);
			case INVOKE_SPECIAL:
			case INVOKE_VIRTUAL:
				ConstantPoolMethodReferenceInfo methodReferenceInfo =
					(ConstantPoolMethodReferenceInfo) constantPool[offset];
				name_and_type_index = methodReferenceInfo.getNameAndTypeIndex();
				break;
			default:
				throw new IllegalArgumentException("unimplemented method type: " + type.name());
		}
		ConstantPoolNameAndTypeInfo methodNameAndType =
			(ConstantPoolNameAndTypeInfo) constantPool[name_and_type_index];
		int descriptor_index = methodNameAndType.getDescriptorIndex();
		ConstantPoolUtf8Info descriptorInfo = (ConstantPoolUtf8Info) constantPool[descriptor_index];
		descriptor = descriptorInfo.getString();
		return descriptor;
	}

	/**
	 * Resolves the datatype represented by {@code fullyQualifiedName} with a base type of
	 * {@code baseType} into dtm
	 * @param fullyQualifiedName String representation of type
	 * @param dtm data type manager
	 * @param baseType base type 
	 * @return data type represented by input string
	 */
	public static DataType resolveClassForString(String fullyQualifiedName, DataTypeManager dtm,
			DataType baseType) {
		fullyQualifiedName = CategoryPath.DELIMITER_CHAR + fullyQualifiedName;
		CategoryPath catPath = new CategoryPath(fullyQualifiedName);
		String[] parts = catPath.getPathElements();
		DataType dataType = new TypedefDataType(catPath, parts[parts.length - 1], baseType);
		dtm.resolve(dataType, DataTypeConflictHandler.KEEP_HANDLER);
		return dataType;
	}

	/**
	 * Returns a String representing the types of the parameters of a method, e.g.
	 * (java.lang.String, java.lang.Integer) for a method with signature
	 * public static void test(String x, Integer y);
	 * @param descriptor method descriptor
	 * @return string representation of types of method parameters
	 */
	public static String getParameterString(String descriptor) {
		List<String> paramTypeNames = getTypeNameList(descriptor, true, true);
		StringBuilder sb = new StringBuilder();
		sb.append("(");
		//don't append the last element of the list, which is the return type
		for (int i = 0, max = paramTypeNames.size() - 1; i < max; ++i) {
			sb.append(paramTypeNames.get(i));
			if (i < max - 1) {
				sb.append(", ");
			}
		}
		sb.append(")");
		return sb.toString();
	}

}
