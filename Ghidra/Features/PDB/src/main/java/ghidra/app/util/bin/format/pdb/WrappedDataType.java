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
package ghidra.app.util.bin.format.pdb;

import ghidra.program.model.data.DataType;

/**
 * <code>WrappedDataType</code> provide the ability to wrap 
 * a {@link DataType} with additional information not conveyed
 * by the datatype on its' own. 
 * <P>
 * Note that a BitFieldDataType instance may be specified as the datatype
 * in order to convey bitfield related information.
 */
public class WrappedDataType {

	private final boolean isZeroLengthArray;
	private final DataType dataType;

	/**
	 * Constructed wrapped datatype
	 * @param dataType datatype
	 * @param isZeroLengthArray true if datatype corresponds to a zero-length 
	 * array which can not directly be represented as an Array datatype, 
	 * else false for all other cases.
	 */
	protected WrappedDataType(DataType dataType, boolean isZeroLengthArray) {
		this.dataType = dataType;
		this.isZeroLengthArray = isZeroLengthArray;
	}

	/**
	 * @return datatype
	 */
	public DataType getDataType() {
		return dataType;
	}

	/**
	 * @return true if datatype corresponds to a zero-length array 
	 * which can not directly be represented as an Array datatype, 
	 * else false for all other cases.
	 */
	public boolean isZeroLengthArray() {
		return isZeroLengthArray;
	}
}
