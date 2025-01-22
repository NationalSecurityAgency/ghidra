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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PascalString255DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * An variable length OMF string
 */
public class OmfString implements StructConverter {

	private int length;
	private String str;

	/**
	 * Creates a new {@link OmfString}
	 * 
	 * @param length The length of the string
	 * @param str The string
	 */
	public OmfString(int length, String str) {
		this.length = length;
		this.str = str;
	}

	/**
	 * {@return the length of the string}
	 */
	public int length() {
		return length;
	}

	/**
	 * {@return the string}
	 */
	public String str() {
		return str;
	}

	/**
	 * {@return the length (in bytes) of this data type}
	 */
	public int getDataTypeSize() {
		return BYTE.getLength() + length;
	}

	@Override
	public String toString() {
		return str;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		if (length == 0) {
			return BYTE;
		}

		return new PascalString255DataType();
	}
}
