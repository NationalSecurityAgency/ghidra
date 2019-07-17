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
import ghidra.util.Conv;

/**
 * A class to represent the new-executable imported name table.
 * 
 * 
 */
public class ImportedNameTable {
    private FactoryBundledWithBinaryReader reader;
    private short index;

    /**
     * Constructs a new imported name table.
     * @param reader the binary reader
     * @param index the index where the table begins
     */
    ImportedNameTable(FactoryBundledWithBinaryReader reader, short index) {
        this.reader = reader;
        this.index = index;
    }

    /**
     * Returns the length/string set at the given offset.
     * 
     * @param offset  The offset, from the beginning of the Imported Name Table,
     *                to the length/string set.
     * 
     * @return the length/string set at the given offset
     */
    public LengthStringSet getNameAt(short offset) throws IOException {
        long oldIndex = reader.getPointerIndex();
        int newIndex = Conv.shortToInt(index)+Conv.shortToInt(offset);
        reader.setPointerIndex(newIndex);
        LengthStringSet lss = new LengthStringSet(reader);
        reader.setPointerIndex(oldIndex);
        return lss;
    }
}
