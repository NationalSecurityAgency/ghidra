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
 * A class for storing new-executable resource string tables.
 * Strings are not stored as individual resources, rather
 * strings are grouped together into a string table. This
 * string table is then stored as a resource.
 * 
 * 
 */
public class ResourceStringTable extends Resource {
    private LengthStringSet [] strings;

	/**
	 * Constucts a new resource string table.
	 * @param reader the binary reade
	 * @param rt the resource table where this resource string table is defined
	 */
    ResourceStringTable(FactoryBundledWithBinaryReader reader, ResourceTable rt) throws IOException {
        super(reader, rt);

        byte [] bytes = getBytes();
        ArrayList<LengthStringSet> list = new ArrayList<LengthStringSet>();
        for (int i = 0 ; i < bytes.length ;) {
            if (bytes[i] != 0) {
                long oldIndex = reader.getPointerIndex();
                reader.setPointerIndex(getFileOffsetShifted()+i);
                LengthStringSet lss = new LengthStringSet(reader);
                if (lss.getLength() == 0) break;
                list.add(lss);
                i += (Conv.byteToInt(lss.getLength())+1);
                reader.setPointerIndex(oldIndex);
            }
            else {
                ++i;
            }
        }
        strings = new LengthStringSet[list.size()];
        list.toArray(strings);
    }

	/**
	 * Returns the strings defined in this resource string table.
	 * @return the strings defined in this resource string table
	 */
    public LengthStringSet [] getStrings() {
        return strings;
    }
}
