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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * A class to manage loading Old-style (MZ) Executables.
 * 
 * 
 */
public class OldStyleExecutable {
	private BinaryReader reader;
    private DOSHeader dosHeader;

    /**
     * Constructs a new instance of an old-style executable
     * @param bp the byte provider
     * @throws IOException if an I/O error occurs
     */
	public OldStyleExecutable(ByteProvider bp) throws IOException {
		reader = new BinaryReader(bp, true);
		dosHeader = new DOSHeader(reader);
    }

    /**
     * Returns the underlying binary reader.
     * @return the underlying binary reader
     */
	public BinaryReader getBinaryReader() {
        return reader;
    }

    /**
     * Returns the DOS Header from this old-style executable.
     * @return the DOS Header from this old-style executable
     */
    public DOSHeader getDOSHeader() {
        return dosHeader;
    }
}
