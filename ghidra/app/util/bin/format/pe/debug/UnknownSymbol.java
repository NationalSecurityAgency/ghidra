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

import ghidra.app.util.bin.format.*;
import ghidra.util.*;

import java.io.*;

/**
 * 
*/
class UnknownSymbol extends DebugSymbol{
    private byte [] unknown;

    static UnknownSymbol createUnknownSymbol(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        UnknownSymbol unknownSymbol = (UnknownSymbol) reader.getFactory().create(UnknownSymbol.class);
        unknownSymbol.initUnknownSymbol(length, type, reader, ptr);
        return unknownSymbol;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public UnknownSymbol() {}

	private void initUnknownSymbol(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);
		try {
			unknown = reader.readByteArray(ptr, Conv.shortToInt(length));
		}
		catch (RuntimeException e) {
		    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	public byte[] getUnknown() {
		return unknown;
	}
}
