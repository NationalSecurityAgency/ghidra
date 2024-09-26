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
import ghidra.util.exception.DuplicateNameException;

/**
 * An OMF index that is either 1 or 2 bytes
 */
public class OmfIndex implements StructConverter {

	private int length;
	private int value;

	/**
	 * Creates a new {@link OmfIndex}
	 * 
	 * @param length 1 or 2
	 * @param value The 1 or 2 byte index value
	 */
	public OmfIndex(int length, int value) {
		this.length = length;
		this.value = value;
	}

	/**
	 * {@return the length of the index (1 or 2)}
	 */
	public int length() {
		return length;
	}

	/**
	 * {@return the index value}
	 */
	public int value() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return length == 2 ? WORD : BYTE;
	}
}
