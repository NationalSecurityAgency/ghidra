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

/**
 * <code>Undefined</code> identifies an undefined data type
 */
public abstract class Undefined extends BuiltIn {

	private final static long serialVersionUID = 1;

	protected Undefined(String name, DataTypeManager dtm) {
		super(CategoryPath.ROOT, name, dtm);
	}

	private static Undefined[] undefinedTypes;

	private synchronized static Undefined[] getUndefinedTypes() {
		if (undefinedTypes == null) {
			undefinedTypes =
				new Undefined[] { Undefined1DataType.dataType, Undefined2DataType.dataType,
					Undefined3DataType.dataType, Undefined4DataType.dataType,
					Undefined5DataType.dataType, Undefined6DataType.dataType,
					Undefined7DataType.dataType, Undefined8DataType.dataType };
		}
		return undefinedTypes;
	}

	/**
	 * Get an Undefined data-type instance of the requested size
	 * @param size data type size, sizes greater than 8 will cause an Undefined1[size] (i.e., Array) to be returned.
	 * @return Undefined data type
	 */
	public static DataType getUndefinedDataType(int size) {
		if (size < 1) {
			return DefaultDataType.dataType;
		}
		if (size > 8) {
			return new ArrayDataType(Undefined1DataType.dataType, size, 1);
		}
		return getUndefinedTypes()[size - 1];
	}

	public static Undefined[] getUndefinedDataTypes() {
		return getUndefinedTypes().clone();
	}

	/**
	 * Determine if the specified dataType is either a DefaultDataType, 
	 * an Undefined data-type, or an Array of Undefined data-types.
	 * @param dataType
	 * @return true if dataType represents an undefined data-type in
	 * its various forms, else false.
	 */
	public static boolean isUndefined(DataType dataType) {
		if (dataType instanceof DefaultDataType) {
			return true;
		}
		if (dataType instanceof Undefined) {
			return true;
		}
		return isUndefinedArray(dataType);
	}

	/**
	 * Determine if the specified dataType is an undefined array
	 * used to represent large undefined data.
	 * @param dataType
	 * @return true if the specified dataType is an undefined array
	 * used to represent large undefined data, otherwise false.
	 */
	public static boolean isUndefinedArray(DataType dataType) {
		if (!(dataType instanceof Array)) {
			return false;
		}
		DataType baseType = ((Array) dataType).getDataType();
		return (baseType instanceof Undefined) || (baseType instanceof DefaultDataType);
	}

}
