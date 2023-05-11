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
package ghidra.program.model.data.ISF;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

public class IsfUtilities {

	// list of Ghidra built-in type names which correspond to C primitive types
	private static String[] INTEGRAL_TYPES = { "char", "short", "int", "long", "long long",
		"__int64", "float", "double", "long double", "void" };

	private static String[] INTEGRAL_MODIFIERS =
		{ "signed", "unsigned", "const", "static", "volatile", "mutable", };

	public static boolean isIntegral(String typedefName, String basetypeName) {
		for (String type : INTEGRAL_TYPES) {
			if (typedefName.equals(type)) {
				return true;
			}
		}

		boolean endsWithIntegralType = false;
		for (String type : INTEGRAL_TYPES) {
			if (typedefName.endsWith(" " + type)) {
				endsWithIntegralType = true;
				break;
			}
		}
		boolean containsIntegralModifier = false;
		for (String modifier : INTEGRAL_MODIFIERS) {
			if (typedefName.indexOf(modifier + " ") >= 0 ||
				typedefName.indexOf(" " + modifier) >= 0) {
				return true;
			}
		}

		if (endsWithIntegralType && containsIntegralModifier) {
			return true;
		}

		if (typedefName.endsWith(" " + basetypeName)) {
			return containsIntegralModifier;
		}

		return false;
	}

	public static DataType getBaseDataType(DataType dt) {
		while (dt != null) {
			if (dt instanceof Array) {
				Array array = (Array) dt;
				dt = array.getDataType();
			}
			else if (dt instanceof Pointer) {
				Pointer pointer = (Pointer) dt;
				dt = pointer.getDataType();
			}
			else if (dt instanceof BitFieldDataType) {
				BitFieldDataType bitfieldDt = (BitFieldDataType) dt;
				dt = bitfieldDt.getBaseDataType();
			}
			else {
				break;
			}
		}
		return dt;
	}

	public static DataType getArrayBaseType(Array arrayDt) {
		DataType dataType = arrayDt.getDataType();
		while (dataType instanceof Array) {
			dataType = ((Array) dataType).getDataType();
		}
		return dataType;
	}

	public static DataType getPointerBaseDataType(Pointer p) {
		DataType dt = p.getDataType();
		while (dt instanceof Pointer) {
			dt = ((Pointer) dt).getDataType();
		}
		return dt;
	}

	public static String getKind(DataType dt) {
		if (dt instanceof Array) {
			return "array";
		}
		if (dt instanceof Structure) {
			return "struct";
		}
		if (dt instanceof Union) {
			return "union";
		}
		if (dt instanceof BuiltInDataType) {
			return "base";
		}
		if (dt instanceof Pointer) {
			return "pointer";
		}
		if (dt instanceof Enum) {
			return "enum";
		}
		if (dt instanceof TypeDef) {
			return "base"; //"typedef";
		}
		if (dt instanceof FunctionDefinition) {
			return "function";
		}
		if (dt instanceof BitFieldDataType) {
			return "bitfield";
		}
		if (dt instanceof DefaultDataType) {
			return "base";
		}
		return "UNKNOWN";
	}

	public static String getBuiltInKind(BuiltInDataType dt) {
		if (dt instanceof AbstractIntegerDataType) {
			return dt.getLength() == 1 ? "char" : "int";
		}
		if (dt instanceof AbstractFloatDataType) {
			return "float";
		}
		if (dt instanceof AbstractComplexDataType) {
			return "complex";
		}
		if (dt instanceof AbstractStringDataType) {
			return "char"; // "string";
		}
		if (dt instanceof PointerDataType) {
			return "void"; //"pointer";
		}
		if (dt instanceof VoidDataType) {
			return "void";
		}
		if (dt instanceof Undefined) {
			return "void";
		}
		return "char";
	}

	public static boolean isBaseDataType(DataType dt) {
		if (dt instanceof AbstractIntegerDataType) {
			return true;
		}
		if (dt instanceof AbstractFloatDataType) {
			return true;
		}
		if (dt instanceof AbstractComplexDataType) {
			return true;
		}
		if (dt instanceof AbstractStringDataType) {
			return true;
		}
		if (dt instanceof Pointer) {
			return true;
		}
		if (dt instanceof VoidDataType) {
			return true;
		}
		if (dt instanceof Undefined) {
			return true;
		}
		return false;
	}

	public static Integer getLength(DataType dt) {
		return dt.getLength();
	}

	public static Boolean getSigned(DataType dt) {
		return dt.getDataOrganization().isSignedChar();
	}

	public static String getEndianness(DataType dt) {
		return dt.getDataOrganization().isBigEndian() ? "big" : "little";
	}
}
