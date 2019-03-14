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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;

/**
 * A class to represent the COFF Line number data structure.
 * <br>
 * <pre>
 * typedef struct _IMAGE_LINENUMBER {
 *    union {
 *        DWORD   SymbolTableIndex; // Symbol table index of function name if Linenumber is 0.
 *        DWORD   VirtualAddress;   // Virtual address of line number.
 *    } Type;
 *    WORD    Linenumber;           // Line number.
 * } IMAGE_LINENUMBER;
 * </pre>
 */
public class DebugCOFFLineNumber {
	/**
	 * The size of the <code>IMAGE_LINENUMBER</code> structure.
	 */
    public final static int IMAGE_SIZEOF_LINENUMBER = 6;

    private int symbolTableIndex;
    private int virtualAddress;
    private int lineNumber;

    public static DebugCOFFLineNumber createDebugCOFFLineNumber(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        DebugCOFFLineNumber debugCOFFLineNumber = (DebugCOFFLineNumber) reader.getFactory().create(DebugCOFFLineNumber.class);
        debugCOFFLineNumber.initDebugCOFFLineNumber(reader, index);
        return debugCOFFLineNumber;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DebugCOFFLineNumber() {}

    private void initDebugCOFFLineNumber(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        symbolTableIndex = reader.readInt(index);
        virtualAddress   = reader.readInt(index);
        index += BinaryReader.SIZEOF_INT;
		lineNumber = Conv.shortToInt(reader.readShort(index));
    }

	/**
	 * Returns the symbol table index of function name, if linenumber is 0.
	 * @return the symbol table index of function name, if linenumber is 0
	 */
    public int getSymbolTableIndex() {
        return symbolTableIndex;
    }
    /**
     * Returns the virtual address of the line number.
     * @return the virtual address of the line number
     */
    public int getVirtualAddress() {
        return virtualAddress;
    }
    /**
     * Returns the line number.
     * @return the line number
     */
    public int getLineNumber() {
        return lineNumber;
    }
}
