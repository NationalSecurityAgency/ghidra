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

import java.io.IOException;
import java.util.ArrayList;

/**
 * A class to represent the new-executable non-resident name table.
 * 
 * 
 */
public class NonResidentNameTable {
    private String title = "<not set>";
    private LengthStringOrdinalSet [] names;

    /**
     * Constructs a new non-resident name table.
     * @param reader the binary reader
     * @param index the index where the non-resident name table begins
     * @param byteCount the number of bytes in the non-resident name table
     */
    NonResidentNameTable(FactoryBundledWithBinaryReader reader, int index, short byteCount) throws IOException {
        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(index);

        ArrayList<LengthStringOrdinalSet> list = new ArrayList<LengthStringOrdinalSet>();
        while (true) {
            LengthStringOrdinalSet lsos = new LengthStringOrdinalSet(reader);
            if (lsos.getLength() == 0) break;
            if (lsos.getOrdinal() == 0) {
                title = lsos.getString();
            }
            list.add(lsos);
        }
        names = new LengthStringOrdinalSet[list.size()];
        list.toArray(names);

        reader.setPointerIndex(oldIndex);
    }

	/**
	 * Returns the non-resident name table title.
	 * @return the non-resident name table title
	 */
    public String getTitle() {
        return title;
    }

	/**
	 * Returns the array of names defined in the non-resident name table.
	 * @return the array of names defined in the non-resident name table
	 */
    public LengthStringOrdinalSet [] getNames() {
        return names;
    }
}
