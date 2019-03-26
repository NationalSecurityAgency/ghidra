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

import java.io.IOException;

import ghidra.app.util.bin.format.*;

/**
 * A class to hold a length/string/ordinal set.
 */
public class LengthStringOrdinalSet extends LengthStringSet {
    private short ordinal;

    /**
     * Constructs a new length/string/ordinal set.
     * @param reader the binary reader
     */
    LengthStringOrdinalSet(FactoryBundledWithBinaryReader reader) throws IOException {
        super(reader);

        if (getLength() == 0) return;

        ordinal = reader.readNextShort();
    }

    /**
     * Returns the ordinal value.
     * @return the ordinal value
     */
    public short getOrdinal() {
        return ordinal;
    }
}
