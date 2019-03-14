/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.mem.MemBuffer;

/**
 * An instance of a DataType that is applicable for a given context.  Most
 * dataTypes are not context sensitive and are suitable for use anywhere.
 * Others like dynamic structures need to create an instance that wraps the
 * data type.
 * 
 * It helps for situations where a data type must have a length.
 */
public class DataTypeInstance {

	private DataType dataType;
	private int length;

	/**
	 * Create an instance of a data type with the given length.
	 * 
	 * @param dt data type
	 * @param length fixed length of the data type
	 */
	protected DataTypeInstance(DataType dt, int length) {
		this.dataType = dt;
		this.length = length;
		if (length < 1) {
			length = dt.getLength() > 0 ? dt.getLength() : 1;
		}
	}

	/**
	 * @return the data type
	 */
	public DataType getDataType() {
		return dataType;
	}

	/**
	 * @return the fixed length of the data type
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Set the length of this data type instance
	 */
	public void setLength(int length) {
		this.length = length;
	}

	/**
	 * Generate a data-type instance
	 * Factory and Dynamic data-types are NOT handled.
	 * @param dataType
	 * @param buf
	 * @return data-type instance or null if one could not be determined
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, MemBuffer buf) {
		return getDataTypeInstance(dataType, buf, -1);
	}

	/**
	 * Attempt to create a fixed-length data-type instance.
	 * Factory and non-sizable Dynamic data-types are NOT handled.
	 * @param dataType
	 * @param length length for sizable Dynamic data-types, otherwise ignored
	 * @return data-type instance or null if unable to create instance.
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, int length) {
		if (dataType == null) {
			return null;
		}
		if (dataType instanceof FactoryDataType) {
			return null;
		}
		boolean isFunctionDef = (dataType instanceof FunctionDefinition);
		if (dataType instanceof TypeDef) {
			isFunctionDef = (((TypeDef) dataType).getBaseDataType() instanceof FunctionDefinition);
		}
		if (isFunctionDef) {
			dataType = new PointerDataType(dataType, -1, dataType.getDataTypeManager());
			length = dataType.getLength();
		}
		else if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			if (length <= 0 || !dynamicDataType.canSpecifyLength()) {
				return null;
			}
		}
		else {
			length = dataType.getLength();
		}

		if (length < 0) {
			return null;
		}

		return new DataTypeInstance(dataType, length);
	}

	@Override
	public String toString() {
		return dataType.toString();
	}

	/**
	 * Attempt to create a data-type instance associated with a specific memory location.
	 * Factory and Dynamic data-types are handled.
	 * @param dataType
	 * @param buf memory location
	 * @param length length for sizable Dynamic data-types, otherwise ignored
	 * @return data-type instance or null if unable to create instance.
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, MemBuffer buf, int length) {
		if (dataType instanceof FactoryDataType) {
			dataType = ((FactoryDataType) dataType).getDataType(buf);
			length = -1; // ignore user-specified length for factory use
		}

		if (dataType == null) {
			return null;
		}
		boolean isFunctionDef = (dataType instanceof FunctionDefinition);
		if (dataType instanceof TypeDef) {
			isFunctionDef = (((TypeDef) dataType).getBaseDataType() instanceof FunctionDefinition);
		}
		if (isFunctionDef) {
			// For use of function definition pointer
			dataType = new PointerDataType(dataType, -1, dataType.getDataTypeManager());
			length = dataType.getLength();
		}
		else if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			length = dynamicDataType.getLength(buf, length);
		}
		else {
			length = dataType.getLength();
		}

		if (length < 0) {
			return null;
		}

		return new DataTypeInstance(dataType, length);
	}
}
