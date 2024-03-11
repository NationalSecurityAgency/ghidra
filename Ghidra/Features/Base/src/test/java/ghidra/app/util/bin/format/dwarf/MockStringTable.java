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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.*;

public class MockStringTable extends StringTable {

	public MockStringTable(BinaryReader reader) {
		super(new BinaryReader(new ByteArrayProvider(new byte[4 * 1024]), true /* LE */));
	}

	public void add(int index, String s) throws IOException {
		s = s + "\0";
		byte[] stringBytes = s.getBytes(StandardCharsets.UTF_8);
		ByteProvider bp = reader.getByteProvider();
		byte[] allBytes = bp.readBytes(0, bp.length());
		if ((index + stringBytes.length) >= allBytes.length) {
			byte[] newBytes = new byte[index + stringBytes.length];
			System.arraycopy(allBytes, 0, newBytes, 0, allBytes.length);
			allBytes = newBytes;
		}
		System.arraycopy(stringBytes, 0, allBytes, index, stringBytes.length);
		reader = new BinaryReader(new ByteArrayProvider(allBytes), true /* LE */);
		cache.clear();
	}

}
