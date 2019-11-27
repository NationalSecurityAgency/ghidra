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
package ghidra.app.util.bin.format.ne;

import java.io.IOException;

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.program.model.address.SegmentedAddress;

/**
 * A class to manage loading New Executables (NE).
 * 
 * 
 */
public class NewExecutable {
    private FactoryBundledWithBinaryReader reader;
    private DOSHeader dosHeader;
    private WindowsHeader winHeader;

    /**
	 * Constructs a new instance of an new executable.
	 * @param factory is the object factory to bundle with the reader
	 * @param bp the byte provider
	 * @param baseAddr the image base of the executable
	 * @throws IOException if an I/O error occurs.
	 */
	public NewExecutable(GenericFactory factory, ByteProvider bp, SegmentedAddress baseAddr)
			throws IOException {
        reader = new FactoryBundledWithBinaryReader(factory, bp, true);
        dosHeader = DOSHeader.createDOSHeader(reader);

        if (dosHeader.isDosSignature()) {
            try {
				winHeader = new WindowsHeader(reader, baseAddr, (short) dosHeader.e_lfanew());
            }
            catch (InvalidWindowsHeaderException e) {
            }
        }
    }
    /**
     * Returns the underlying binary reader.
     * @return the underlying binary reader
     */
    public FactoryBundledWithBinaryReader getBinaryReader() {
        return reader;
    }
    /**
     * Returns the DOS header from the new executable.
     * @return the DOS header from the new executable
     */
    public DOSHeader getDOSHeader() {
        return dosHeader;
    }
    /**
     * Returns the Windows header from the new executable.
     * @return the Windows header from the new executable
     */
    public WindowsHeader getWindowsHeader() {
        return winHeader;
    }
}
