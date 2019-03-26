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

/**
 * A class to represent the S_BPREL32_NEW data structure.
 * 
 */
public class S_BPREL32_NEW extends DebugSymbol {
    private short  variableType;
	private short  symbolType;

    static S_BPREL32_NEW createS_BPREL32_NEW(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        S_BPREL32_NEW s_bprel32_new = (S_BPREL32_NEW) reader.getFactory().create(S_BPREL32_NEW.class);
        s_bprel32_new.initS_BPREL32_NEW(length, type, reader, ptr);
        return s_bprel32_new;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_BPREL32_NEW() {}

    private void initS_BPREL32_NEW(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);

		offset        = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
		variableType  = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
		symbolType    = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;

		byte nameLen = reader.readByte (ptr); ptr+=BinaryReader.SIZEOF_BYTE;

		name = reader.readAsciiString(ptr, Conv.byteToInt(nameLen));
	}

	/**
	 * Returns the variable type.
	 * @return the variable type
	 */
	public short getVariableType() {
	    return variableType;
	}
	short getSymbolType() {
		return symbolType;
	}
}
