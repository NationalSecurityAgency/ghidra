/* ###
 * IP: GHIDRA
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
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;

/**
 * A class to represent the new-executable resident name table.
 * 
 */
public class ResidentNameTable {
    private LengthStringOrdinalSet [] names;

	ResidentNameTable(BinaryReader reader, short index) throws IOException {
        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(Short.toUnsignedInt(index));

        ArrayList<LengthStringOrdinalSet> list = new ArrayList<LengthStringOrdinalSet>();
        while (true) {
            LengthStringOrdinalSet lsos = new LengthStringOrdinalSet(reader);
            if (lsos.getLength() == 0) break;
            list.add(lsos);
        }
        names = new LengthStringOrdinalSet[list.size()];
        list.toArray(names);

        reader.setPointerIndex(oldIndex);
    }

	/**
	 * Returns the array of names defined in the resident name table.
	 * @return the array of names defined in the resident name table
	 */
    public LengthStringOrdinalSet [] getNames() {
        return names;
    }
}
