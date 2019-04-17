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
import java.util.ArrayList;

/**
 * A class to represent the new-executable module reference table.
 * 
 * 
 */
public class ModuleReferenceTable {
    private short [] offsets;
    private LengthStringSet [] names;

    /**
     * Constructs a new module reference table.
     * @param reader the binary reader
     * @param index the index where the table begins
     * @param count the count of modules referenced
     * @param imp the imported name table
     */
    ModuleReferenceTable(FactoryBundledWithBinaryReader reader, short index, short count, ImportedNameTable imp) throws IOException {
        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(Conv.shortToInt(index));

        offsets = new short[Conv.shortToInt(count)];
        for (short i = 0 ; i < count ; ++i) {
            offsets[i] = reader.readNextShort();
        }

        ArrayList<LengthStringSet> list = new ArrayList<LengthStringSet>();
        for (int i = 0 ; i < offsets.length ; ++i) {
            LengthStringSet lss = imp.getNameAt(offsets[i]);
            if (lss.getLength() == 0) break;
            list.add(lss);
        }
        names = new LengthStringSet[list.size()];
        list.toArray(names);

        reader.setPointerIndex(oldIndex);
    }

    /**
     * Returns the array of names.
     * @return the array of names
     */
    public LengthStringSet [] getNames() {
        return names;
    }

    /**
     * Returns the array of offsets.
     * @return the array of offsets
     */
    public short [] getOffsets() {
        return offsets;
    }
}
