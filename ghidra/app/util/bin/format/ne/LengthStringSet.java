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

import ghidra.app.util.bin.format.*;
import ghidra.util.Conv;

import java.io.IOException;

/**
 * A class to store a length/string set,
 * where the string is not null-terminated
 * and the length field determines the string
 * length
 * 
 * 
 */
public class LengthStringSet {
    private long    index;  //byte index where this string is located...
    private byte   length;
    private String name;

    /**
     * Constructs a new length/string set.
     * @param reader the binary reader
     */
    LengthStringSet(FactoryBundledWithBinaryReader reader) throws IOException {
        index = reader.getPointerIndex();

        length = reader.readNextByte();
        if (length == 0) return;

        name = reader.readNextAsciiString(Conv.byteToInt(length)); //not null-terminated
    }

    /**
     * Returns the byte index of this string,
     * relative to the beginning of the file.
     * @return the byte index of this string
     */
    public long getIndex() {
        return index;
    }

    /**
     * Returns the length of the string.
     * @return the length of the string
     */
    public byte getLength() {
        return length;
    }

    /**
     * Returns the string.
     * @return the string
     */
    public String getString() {
        return name;
    }
}
