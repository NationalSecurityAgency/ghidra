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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.util.*;

import java.io.*;
import java.util.*;

/**
 * A class to represent the Object Module Format (OMF) Global data structure.
 * 
 */
public class OMFGlobal {
    private short symHash;
	private short addrHash;
	private int   cbSymbol;
	private int   cbSymHash;
	private int   cbAddrHash;
	private ArrayList<DebugSymbol> symbols = new ArrayList<DebugSymbol>();

    static OMFGlobal createOMFGlobal(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFGlobal omfGlobal = (OMFGlobal) reader.getFactory().create(OMFGlobal.class);
        omfGlobal.initOMFGlobal(reader, ptr);
        return omfGlobal;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFGlobal() {}

	private void initOMFGlobal(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		symHash    = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
		addrHash   = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
		cbSymbol   = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
		cbSymHash  = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
		cbAddrHash = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;

		int bytesLeft = cbSymbol;

		while (bytesLeft > 0) {
			DebugSymbol sym = DebugSymbolSelector.selectSymbol(reader, ptr);

			ptr       += 2*BinaryReader.SIZEOF_SHORT;
			bytesLeft -= 2*BinaryReader.SIZEOF_SHORT; 

			if (sym != null) {
				symbols.add(sym);

				int recLen = Conv.shortToInt(sym.getLength());
				bytesLeft -= recLen;
				ptr       += recLen-2;
			}
		}
	}

	public short getAddrHash() {
		return addrHash;
	}
	public int getCbAddrHash() {
		return cbAddrHash;
	}
	public int getCbSymbol() {
		return cbSymbol;
	}
	public int getCbSymHash() {
		return cbSymHash;
	}
	public short getSymHash() {
		return symHash;
	}

	/**
	 * Returns the debug symbols in this OMF Global.
	 * @return the debug symbols in this OMF Global
	 */
	public List<DebugSymbol> getSymbols() {
		return symbols;
	}
}
