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

/**
 *
 * Container object for a DataType and a byte array that is the format for
 * the data type. 
 * 
 * 
 */
public class CustomFormat {

	private DataType dataType;
	private byte[] format;

	/**
	 * Constructor
	 * @param dataType data type associated with this format
	 * @param format bytes that define the format
	 */
	public CustomFormat(DataType dataType, byte[] format) {
		this.dataType = dataType;
		this.format = format;
	}

	/**
	 * Get the data type associated with this format.
	 */
	public DataType getDataType() {
		return dataType;
	}

	/**
	 * Get the bytes that define this format.
	 */
	public byte[] getBytes() {
		return format;
	}

}
