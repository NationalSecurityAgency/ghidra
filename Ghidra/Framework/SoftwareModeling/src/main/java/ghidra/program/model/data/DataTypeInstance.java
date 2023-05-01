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

import ghidra.program.model.listing.Data;
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
	 * <br>
	 * NOTE: fixed-length primitive datatypes assume {@link DataType#getLength() raw datatype length}
	 * intended for {@link Data} use.
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

	@Override
	public String toString() {
		return dataType.toString();
	}

	/**
	 * Generate a data-type instance
	 * Factory and Dynamic data-types are NOT handled.
	 * @param dataType data type
	 * @param buf memory buffer
	 * @param useAlignedLength if true a fixed-length primitive data type will use its 
	 * {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
	 * {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
	 * float datatypes whose raw encoding length may be shorter than their aligned-length
	 * generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
	 * true for {@link DataTypeComponent} and false for simple {@link Data} instances.
	 * @return data-type instance or null if one could not be determined
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, MemBuffer buf,
			boolean useAlignedLength) {
		return getDataTypeInstance(dataType, buf, -1, useAlignedLength);
	}

	/**
	 * Attempt to create a fixed-length data-type instance.
	 * Factory and non-sizable Dynamic data-types are NOT handled.
	 * @param dataType data type
	 * @param length length for sizable Dynamic data-types, otherwise ignored
	 * @param useAlignedLength if true a fixed-length primitive data type will use its 
	 * {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
	 * {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
	 * float datatypes whose raw encoding length may be shorter than their aligned-length
	 * generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
	 * true for {@link DataTypeComponent} and false for simple {@link Data} instances.
	 * @return data-type instance or null if unable to create instance.
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, int length,
			boolean useAlignedLength) {
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
		else if (useAlignedLength) {
			length = dataType.getAlignedLength();
		}
		else {
			length = dataType.getLength();
		}

		if (length < 0) {
			return null;
		}

		return new DataTypeInstance(dataType, length);
	}

	/**
	 * Attempt to create a data-type instance associated with a specific memory location.
	 * Factory and Dynamic data-types are handled.
	 * <br>
	 * NOTE: fixed-length primitive datatypes assume {@link DataType#getLength() raw datatype length}
	 * intended for {@link Data} use.
	 * 
	 * @param dataType
	 * @param buf memory location
	 * @param length length for sizable Dynamic data-types, otherwise ignored
	 * @param useAlignedLength if true a fixed-length primitive data type will use its 
	 * {@link DataType#getAlignedLength() aligned-length}, otherwise it will use its
	 * {@link DataType#getLength() raw length}.  NOTE: This generally only relates to 
	 * float datatypes whose raw encoding length may be shorter than their aligned-length
	 * generally corresponding to a compiler's "sizeof(type)" value.  This should generally be
	 * true for {@link DataTypeComponent} and false for simple {@link Data} instances.
	 * @return data-type instance or null if unable to create instance.
	 */
	public static DataTypeInstance getDataTypeInstance(DataType dataType, MemBuffer buf, int length,
			boolean useAlignedLength) {
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
		else if (useAlignedLength) {
			length = dataType.getAlignedLength();
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
