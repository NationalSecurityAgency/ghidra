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
import ghidra.app.util.bin.format.dwarf4.LEB128;

public class FileEntry {
	private String   fileName;
	private long directoryIndex;
	private long lastModifiedTime;
	private long fileLengthInBytes;

	FileEntry(BinaryReader reader) throws IOException {
		fileName = reader.readNextAsciiString();
		if (fileName.length() == 0) {
			return;
		}
		directoryIndex = LEB128.readAsLong(reader, false);
		lastModifiedTime = LEB128.readAsLong(reader, false);
		fileLengthInBytes = LEB128.readAsLong(reader, false);
	}

	public String getFileName() {
		return fileName;
	}
	public long getDirectoryIndex() {
		return directoryIndex;
	}
	public long getLastModifiedTime() {
		return lastModifiedTime;
	}
	public long getFileLengthInBytes() {
		return fileLengthInBytes;
	}

	@Override
	public String toString() {
		return fileName;
	}
}
