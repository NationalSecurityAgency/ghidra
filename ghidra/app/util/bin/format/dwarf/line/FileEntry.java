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
package ghidra.app.util.bin.format.dwarf.line;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class FileEntry {
	private String   fileName;
	private LEB128   directoryIndex;
	private LEB128   lastModifiedTime;
	private LEB128   fileLengthInBytes;

	FileEntry(BinaryReader reader) throws IOException {
		fileName = reader.readNextAsciiString();
		if (fileName.length() == 0) {
			return;
		}
		directoryIndex = new LEB128(reader, false);
		lastModifiedTime = new LEB128(reader, false);
		fileLengthInBytes = new LEB128(reader, false);
	}

	public String getFileName() {
		return fileName;
	}
	public LEB128 getDirectoryIndex() {
		return directoryIndex;
	}
	public LEB128 getLastModifiedTime() {
		return lastModifiedTime;
	}
	public LEB128 getFileLengthInBytes() {
		return fileLengthInBytes;
	}

	@Override
	public String toString() {
		return fileName;
	}
}
