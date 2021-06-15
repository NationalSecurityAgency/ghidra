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
package ghidra.program.model.data;

public enum MetaDataType {
	// Enumerations are ordered in terms of how "specific" the data-type class is
	VOID,		// "void" data-type
	UNKNOWN,	// An unknown/undefined data-type
	INT,		// Signed integer
	UINT,		// Unsigned integer
	BOOL,		// Boolean
	CODE,		// Executable code
	FLOAT,		// Floating-point
	PTR,		// Pointer
	ARRAY,		// Array
	STRUCT;		// Structured data-type

	public static MetaDataType getMeta(DataType dt) {
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		if (dt instanceof DefaultDataType || dt instanceof Undefined) {
			return UNKNOWN;
		}
		if (dt instanceof AbstractIntegerDataType) {
			if (dt instanceof BooleanDataType) {
				return BOOL;
			}
			if (((AbstractIntegerDataType) dt).isSigned()) {
				return INT;
			}
			return UINT;
		}
		if (dt instanceof Pointer) {
			return PTR;
		}
		if (dt instanceof Array) {
			return ARRAY;
		}
		if (dt instanceof Structure) {
			return STRUCT;
		}
		if (dt instanceof AbstractFloatDataType) {
			return FLOAT;
		}
		if (dt instanceof ArrayStringable) {
			return INT;
		}
		if (dt instanceof FunctionDefinition) {
			return CODE;
		}
		if (dt instanceof Enum) {
			return UINT;
		}
		if (dt instanceof AbstractStringDataType) {
			return ARRAY;
		}
		return STRUCT;
	}

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
			MetaDataType aMeta = MetaDataType.getMeta(a);
			MetaDataType bMeta = MetaDataType.getMeta(b);
			int compare = aMeta.compareTo(bMeta);
			if (compare < 0) {
				return bCopy;
			}
			else if (compare > 0) {
				return aCopy;
			}
			if (aMeta == MetaDataType.PTR) {
				if (a instanceof TypeDef) {
					a = ((TypeDef) a).getBaseDataType();
				}
				if (b instanceof TypeDef) {
					b = ((TypeDef) b).getBaseDataType();
				}
				a = ((Pointer) a).getDataType();
				b = ((Pointer) b).getDataType();
			}
			else if (aMeta == MetaDataType.ARRAY) {
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
