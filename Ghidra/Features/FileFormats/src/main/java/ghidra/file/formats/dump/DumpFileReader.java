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
package ghidra.file.formats.dump;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class DumpFileReader extends BinaryReader {

	private int size;

	public DumpFileReader(ByteProvider provider, boolean isLittleEndian, int size) {
		super(provider, isLittleEndian);
		this.size = size;
	}

	public long readNextPointer() throws IOException {
		return size == 32 ? readNextInt() : readNextLong();
	}

	public long readPointer(long offset) throws IOException {
		return size == 32 ? readInt(offset) : readLong(offset);
	}

	public int getPointerSize() {
		return size / 8;
	}

	public void setPointerSize(int size) {
		this.size = size;
	}

}
