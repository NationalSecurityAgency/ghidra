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
package ghidra.app.util.bin.format.dwarf.line;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class LEB128 {
	private long value;

	LEB128(BinaryReader reader, boolean isSigned) throws IOException {
		if (isSigned) {
			throw new UnsupportedOperationException();
		}
		int shift = 0;
		while (true) {
			int nextByte = reader.readNextByte() & 0xff;
			value |= ((nextByte & 0x7f) << shift);
			if ((nextByte & 0x80) == 0) {
				break;
			}
			shift += 7;
		}
	}

	long getValue() {
		return value;
	}

	@Override
	public String toString() {
		return "0x" + Long.toHexString(value);
	}
}
