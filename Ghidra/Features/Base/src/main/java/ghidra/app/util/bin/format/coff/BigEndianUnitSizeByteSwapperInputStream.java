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
package ghidra.app.util.bin.format.coff;

import java.io.IOException;
import java.io.InputStream;

/**
 * All COFF files are stored as little endian.
 * However, for COFF binaries targeted for WORD addressable
 * big endian processors, the bytes for the section
 * must be swapped inside the addressable unit.
 */
class BigEndianUnitSizeByteSwapperInputStream extends InputStream {
	private InputStream input;
	private int unitSize;
	private int [] array;
	private int arrayPosition = -1;

	BigEndianUnitSizeByteSwapperInputStream(InputStream input, int unitSize) {
		this.input = input;
		this.unitSize = unitSize;
		this.array = new int[unitSize];
	}

	@Override
	public synchronized int read() throws IOException {
		if (arrayPosition == -1) {
			for (int i = 0 ; i < unitSize ; ++i) {
				array[i] = input.read();
			}
			arrayPosition = unitSize - 1;
		}
		return array[arrayPosition--];
	}

}
