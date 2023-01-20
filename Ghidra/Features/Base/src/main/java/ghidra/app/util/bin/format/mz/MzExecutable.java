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
package ghidra.app.util.bin.format.mz;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * A class to manage loading old-style DOS MZ executables
 */
public class MzExecutable {

	private BinaryReader reader;
    private OldDOSHeader header;
	private List<MzRelocation> relocations = new ArrayList<>();

    /**
	 * Constructs a new instance of an old-style MZ executable
	 * 
	 * @param provider The bytes
	 * @throws IOException if an I/O error occurs
	 */
	public MzExecutable(ByteProvider provider) throws IOException {
		reader = new BinaryReader(provider, true);
		header = new OldDOSHeader(reader);
		reader.setPointerIndex(header.e_lfarlc());
		for (int i = 0; i < header.e_crlc(); i++) {
			relocations.add(new MzRelocation(reader));
		}
    }

    /**
	 * Returns the underlying binary reader
	 * 
	 * @return the underlying binary reader
	 */
	public BinaryReader getBinaryReader() {
        return reader;
    }

    /**
	 * Returns the DOS Header from this old-style MZ executable
	 * 
	 * @return the DOS Header from this old-style MZ executable
	 */
    public OldDOSHeader getHeader() {
        return header;
    }

	/**
	 * Returns the old-style MZ relocations
	 * 
	 * @return the old-style MZ relocations
	 */
	public List<MzRelocation> getRelocations() {
		return relocations;
	}
}
