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

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.*;

/**
 * A possible implementation of the FIXUP debug directory elements. 
 * It may be inaccurate and/or incomplete.
 * 
 * 
 */
public class DebugFixupElement {
    final static int SIZEOF = 12;

    private int type;
    private int addr1;
    private int addr2;

    static DebugFixupElement createDebugFixupElement(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        DebugFixupElement debugFixupElement = (DebugFixupElement) reader.getFactory().create(DebugFixupElement.class);
        debugFixupElement.initDebugFixupElement(reader, index);
        return debugFixupElement;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DebugFixupElement() {}

    private void initDebugFixupElement(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        type  = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        addr1 = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
        addr2 = reader.readInt(index); index += BinaryReader.SIZEOF_INT;
    }

	/**
	 * Returns the FIXUP element type.
	 * @return the FIXUP element type
	 */
    public int getType() {
        return type;
    }
    /**
     * Returns the first address of this FIXUP element.
     * @return the first address of this FIXUP element
     */
    public int getAddress1() {
        return addr1;
    }
	/**
	 * Returns the second address of this FIXUP element.
	 * @return the second address of this FIXUP element
	 */
    public int getAddress2() {
        return addr2;
    }
}
