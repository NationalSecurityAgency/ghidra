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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Conv;

/**
 * A class to represent the Object Module Format (OMF) Library data structure.
 * 
 */
public class OMFLibrary {
    private String [] libs;

	OMFLibrary(BinaryReader reader, int ptr, int numBytes) throws IOException {
		ArrayList<String> libList = new ArrayList<String>();
		while (numBytes > 0) {
			byte len = reader.readByte(ptr);
			ptr += BinaryReader.SIZEOF_BYTE;
			numBytes -= BinaryReader.SIZEOF_BYTE;
			int length = Conv.byteToInt(len);
			String lib = reader.readAsciiString(ptr, length);
			ptr += length;
			numBytes -= length;
			libList.add(lib);
		}
		libs = new String[libList.size()];
		libList.toArray(libs);
    }

	/**
	 * Returns the array of library names.
	 * @return the array of library name
	 */
	public String [] getLibraries() {
		return libs;
	}
}
