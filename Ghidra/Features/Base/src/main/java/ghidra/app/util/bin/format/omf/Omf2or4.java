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
 * An OMF value that is either 2 or 4 bytes
 */
public class Omf2or4 implements StructConverter {

	private int length;
	private long value;

	/**
	 * Creates a new {@link Omf2or4}
	 * 
	 * @param length 2 or 4
	 * @param value The 2 or 4 byte value
	 */
	public Omf2or4(int length, long value) {
		this.length = length;
		this.value = value;
	}

	/**
	 * {@return the length of the value (2 or 4)}
	 */
	public int length() {
		return length;
	}

	/**
	 * {@return the value}
	 */
	public long value() {
		return value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return length == 2 ? WORD : DWORD;
	}
}
