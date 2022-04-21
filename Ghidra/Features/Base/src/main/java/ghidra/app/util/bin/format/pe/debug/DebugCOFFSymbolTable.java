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
import ghidra.app.util.bin.format.pe.NTHeader;

/**
 * A class to represent the COFF Symbol Table.
 */
public class DebugCOFFSymbolTable {
    private int ptrToSymbolTable;
    private int symbolCount;

    private DebugCOFFSymbol [] symbols;

	public DebugCOFFSymbolTable(BinaryReader reader, DebugCOFFSymbolsHeader coffHeader, int offset)
			throws IOException {
        this.ptrToSymbolTable = coffHeader.getFirstSymbolLVA() + offset;
        this.symbolCount      = coffHeader.getNumberOfSymbols();

//TODO:
//should symbol table info in NT Header agree with info in COFF Header?

        if (symbolCount > 0 && symbolCount < NTHeader.MAX_SANE_COUNT) {
	        symbols = new DebugCOFFSymbol[symbolCount];
	        for (int i = 0 ; i < symbolCount ; ++i) {
				symbols[i] = new DebugCOFFSymbol(reader,
					ptrToSymbolTable + (i * DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL), this);
	        }
        }
    }

    int getStringTableIndex() {
        return ptrToSymbolTable + (symbolCount * DebugCOFFSymbol.IMAGE_SIZEOF_SYMBOL);
    }

	/**
	 * Returns the COFF symbols defined in this COFF symbol table.
	 * @return the COFF symbols defined in this COFF symbol table
	 */
    public DebugCOFFSymbol [] getSymbols() {
        return symbols;
    }
}
