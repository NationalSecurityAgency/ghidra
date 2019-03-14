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
package ghidra.app.util.bin.format.ne;

import generic.continues.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.app.util.bin.format.mz.*;

import java.io.*;

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
     * @param bp the byte provider
     * @throws IOException if an I/O error occurs.
     */
    public NewExecutable(GenericFactory factory, ByteProvider bp) throws IOException {
        reader = new FactoryBundledWithBinaryReader(factory, bp, true);
        dosHeader = DOSHeader.createDOSHeader(reader);

        if (dosHeader.isDosSignature()) {
            try {
                winHeader = new WindowsHeader(reader, (short)dosHeader.e_lfanew());
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
