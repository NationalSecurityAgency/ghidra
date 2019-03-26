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

import java.io.*;

/** 
 * A class to represent the S_GPROC32_NEW data structure.
 * 
 */
public class S_GPROC32_NEW extends DebugSymbol{
    private int    pParent;
	private int    pEnd;
	private int    pNext;
	private int    procLen;
	private int    debugStart;
	private int    debugEnd;
	private int    procOffset; //offset to start of procedure...
	private short  procType;
	
    static S_GPROC32_NEW createS_GPROC32_NEW(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        S_GPROC32_NEW s_gproc32_new = (S_GPROC32_NEW) reader.getFactory().create(S_GPROC32_NEW.class);
        s_gproc32_new.initS_GPROC32_NEW(length, type, reader, ptr);
        return s_gproc32_new;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_GPROC32_NEW() {}

	private void initS_GPROC32_NEW(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);
		pParent      = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		pEnd         = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		pNext        = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		procLen      = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		debugStart   = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		debugEnd     = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		offset       = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		procOffset   = reader.readInt(ptr); ptr += BinaryReader.SIZEOF_INT;
		section      = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;
		procType     = reader.readShort(ptr); ptr += BinaryReader.SIZEOF_SHORT;
		name         = reader.readAsciiString(ptr); ptr += name.length();
	}

	public int getParent() {
		return pParent;
	}
	public int getEnd() {
		return pEnd;
	}
	public int getNext() {
		return pNext;
	}
	public int getDebugStart() {
		return debugStart;
	}
	public int getDebugEnd() {
		return debugEnd;
	}

	/**
	 * Returns the procedure length.
	 * @return the procedure length
	 */
	public int getProcLen() {
		return procLen;
	}

	/**
	 * Returns the procedure type.
	 * @return the procedure type
	 */
	public short getProcType() {
		return procType;
	}

	/**
	 * Returns the procedure offset.
	 * @return the procedure offset
	 */
	public int getProcOffset() {
		return procOffset;
	}

}
