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
package ghidra.file.formats.android.bootimg;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

import java.io.IOException;

public class PartitionTableEntry {

	private byte[] name;
	private int start;
	private int length;
	private int flags;

	public PartitionTableEntry(ByteProvider provider) throws IOException {
		this(new BinaryReader(provider, true));
	}

	public PartitionTableEntry(BinaryReader reader) throws IOException {
		name = reader.readNextByteArray(16);
		start = reader.readNextInt();
		length = reader.readNextInt();
		flags = reader.readNextInt();
	}

	public String getName() {
		return new String(name);
	}

	public int getStart() {
		return start;
	}

	public int getLength() {
		return length;
	}

	public int getFlags() {
		return flags;
	}
}
