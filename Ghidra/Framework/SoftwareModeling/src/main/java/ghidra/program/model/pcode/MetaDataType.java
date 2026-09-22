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
package ghidra.program.model.pcode;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

/**
 *  Data-type meta-types.  Values must match the decompiler enumeration "type_metatype".
 *  Values are comparable. A lower value indicates a more "specific" data-type.
 */
public enum MetaDataType {
	TYPE_VOID(17, "void"),		// Standard "void" type, absence of type
	TYPE_SPACEBASE(16, "spacebase"),
	TYPE_UNKNOWN(15, "unknown"),		// An unknown low-level type. Treated as an unsigned integer.
	TYPE_INT(14, "int"),		// Signed integer. Signed is considered less specific than unsigned in C
	TYPE_UINT(13, "uint"),		// Unsigned integer
	TYPE_BOOL(12, "bool"),		// Boolean
	TYPE_CODE(11, "code"),		// Data is actual executable code
	TYPE_FLOAT(10, "float"),	// Floating-point

	TYPE_PTR(9, "ptr"),		// Pointer data-type
	TYPE_PTRREL(8, "ptrrel"),	// Pointer relative to another data-type (specialization of TYPE_PTR)
	TYPE_ARRAY(7, "array"),		// Array data-type, made up of a sequence of "element" datatype
	TYPE_ENUM_UINT(6, "enum_uint"),	// Unsigned enumeration (specialization of TYPE_UINT)
	TYPE_ENUM_INT(5, "enum_int"),	// Signed enumeration (specialization of TYPE_INT)
	TYPE_STRUCT(4, "struct"),	// Structure data-type, made up of component datatypes
	TYPE_UNION(3, "union"),		// An overlapping union of multiple datatypes
	TYPE_PARTIALENUM(2, "partenum"),	// A piece of an enumeration
	TYPE_PARTIALSTRUCT(1, "partstruct"),	// A piece of a structure
	TYPE_PARTIALUNION(0, "partunion");	// A piece of a union data-type

	private int value;			// Enum value matching decompiler
	private String name;		// Name for debug marshaling

	private static MetaDataType METATYPE[] = new MetaDataType[18];

	static {
		for (MetaDataType meta : values()) {
			METATYPE[meta.value] = meta;
		}
	}

	private MetaDataType(int val, String nm) {
		value = val;
		name = nm;
	}

	public int getValue() {
		return value;
	}

	@Override
	public String toString() {
		return name;
	}

	public static MetaDataType getById(int id) {
		if (id < 0 || id >= METATYPE.length)
			return null;
		return METATYPE[id];
	}

	/**
	 * Get the decompiler meta-type associated with a data-type.
	 * @param tp is the data-type
	 * @return the meta-type
	 */
	public static MetaDataType get(DataType tp) {
		if (tp instanceof TypeDef) {
			tp = ((TypeDef) tp).getBaseDataType();
		}
		if (tp instanceof Undefined || tp instanceof DefaultDataType) {
			return TYPE_UNKNOWN;
		}
		if (tp instanceof AbstractFloatDataType) {
			return TYPE_FLOAT;
		}
		if (tp instanceof Pointer) {
			return TYPE_PTR;
		}
		if (tp instanceof BooleanDataType) {
			return TYPE_BOOL;
		}
		if (tp instanceof AbstractSignedIntegerDataType) {
			return TYPE_INT;
		}
		if (tp instanceof AbstractUnsignedIntegerDataType) {
			return TYPE_UINT;
		}
		if (tp instanceof Structure) {
			return TYPE_STRUCT;
		}
		if (tp instanceof Union) {
			return TYPE_UNION;
		}
		if (tp instanceof Array) {
			return TYPE_ARRAY;
		}
		if (tp instanceof CharDataType) {
			return ((CharDataType) tp).isSigned() ? TYPE_INT : TYPE_UINT;
		}
		if (tp instanceof WideCharDataType || tp instanceof WideChar16DataType ||
			tp instanceof WideChar32DataType) {
			return TYPE_INT;
		}
		if (tp instanceof Enum) {
			return ((Enum) tp).isSigned() ? TYPE_INT : TYPE_UINT;
		}
		if (tp instanceof FunctionDefinition) {
			return TYPE_CODE;
		}
		if (tp instanceof AbstractStringDataType) {
			return TYPE_ARRAY;
		}
		return TYPE_UNKNOWN;
	}

	/**
	 * Convert an XML marshaling string to a metatype code
	 * @param name is the string
	 * @return the metatype code or null
	 */
	public static MetaDataType get(String name) {
		switch (name.charAt(0)) {
			case 'p':
				if (name.equals("ptr")) {
					return TYPE_PTR;
				}
				if (name.equals("ptrrel")) {
					return TYPE_PTRREL;
				}
				if (name.equals("partenum")) {
					return TYPE_PARTIALENUM;
				}
				if (name.equals("partunion")) {
					return TYPE_PARTIALUNION;
				}
				break;
			case 'a':
				if (name.equals("array")) {
					return TYPE_ARRAY;
				}
				break;
			case 's':
				if (name.equals("struct")) {
					return TYPE_STRUCT;
				}
				if (name.equals("spacebase")) {
					return TYPE_SPACEBASE;
				}
				break;
			case 'u':
				if (name.equals("unknown")) {
					return TYPE_UNKNOWN;
				}
				else if (name.equals("uint")) {
					return TYPE_UINT;
				}
				else if (name.equals("union")) {
					return TYPE_UNION;
				}
				break;
			case 'i':
				if (name.equals("int")) {
					return TYPE_INT;
				}
				break;
			case 'f':
				if (name.equals("float")) {
					return TYPE_FLOAT;
				}
				break;
			case 'b':
				if (name.equals("bool")) {
					return TYPE_BOOL;
				}
				break;
			case 'c':
				if (name.equals("code")) {
					return TYPE_CODE;
				}
				break;
			case 'v':
				if (name.equals("void")) {
					return TYPE_VOID;
				}
				break;
			case 'e':
				if (name.equals("enum_int")) {
					return TYPE_ENUM_INT;
				}
				if (name.equals("enum_uint")) {
					return TYPE_ENUM_UINT;
				}
				break;
			default:
				break;
		}
		return null;
	}

	/**
	 * Return the most "specific" data-type between the two parameters, as determined
	 * by meta-type.
	 * @param a is the first to compare
	 * @param b is the second
	 * @return the most specific data-type
	 */
	public static DataType getMostSpecificDataType(DataType a, DataType b) {
		DataType aCopy = a;
		DataType bCopy = b;
		for (;;) {
			if (a == null) {
				return bCopy;
			}
			if (b == null) {
				return aCopy;
			}
			MetaDataType aMeta = get(a);
			MetaDataType bMeta = get(b);
			if (bMeta.getValue() < aMeta.getValue()) {
				return bCopy;
			}
			else if (aMeta.getValue() < bMeta.getValue()) {
				return aCopy;
			}
			if (aMeta == TYPE_PTR) {
				if (a instanceof TypeDef) {
					a = ((TypeDef) a).getBaseDataType();
				}
				if (b instanceof TypeDef) {
					b = ((TypeDef) b).getBaseDataType();
				}
				a = ((Pointer) a).getDataType();
				b = ((Pointer) b).getDataType();
			}
			else if (aMeta == TYPE_ARRAY) {
				if (a instanceof TypeDef) {
					a = ((TypeDef) a).getBaseDataType();
				}
				if (b instanceof TypeDef) {
					b = ((TypeDef) b).getBaseDataType();
				}
				if (!(a instanceof Array) || !(b instanceof Array)) {
					break;
				}
				a = ((Array) a).getDataType();
				b = ((Array) b).getDataType();
			}
			else {
				break;
			}
		}
		return aCopy;
	}
}
