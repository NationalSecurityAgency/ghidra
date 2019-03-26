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
 * A class for storing the new-executable resource table.
 * A resource table contains all of the supported types
 * of resources.
 * 
 * 
 */
public class ResourceTable {
    private short index;
    private short alignmentShiftCount;
    private ResourceType [] types;
    private ResourceName [] names;

    /**
     * Constructs a new resource table.
     * @param reader the binary reader
     * @param index  the byte index where the Resource Table begins,
     *               (this is relative to the beginning of the file
     */
    ResourceTable(FactoryBundledWithBinaryReader reader, short index) throws IOException {
        this.index = index;

        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(Conv.shortToInt(index));

        alignmentShiftCount = reader.readNextShort();

        ArrayList<ResourceType> typeList = new ArrayList<ResourceType>();
        while (true) {
            ResourceType rt = new ResourceType(reader, this);
            if (rt.getTypeID() == 0) break;
            typeList.add(rt);
        }
        types = new ResourceType[typeList.size()];
        typeList.toArray(types);

        ArrayList<ResourceName> nameList = new ArrayList<ResourceName>();
        while (true) {
            ResourceName rn = new ResourceName(reader);
            if (rn.getLength() == 0) break;
            nameList.add(rn);
        }
        names = new ResourceName[nameList.size()];
        nameList.toArray(names);

        reader.setPointerIndex(oldIndex);
    }

	/**
	 * Returns the alignment shift count. 
	 * Some resources offsets and lengths are stored bit shifted.
	 * @return the alignment shift count
	 */
    public short getAlignmentShiftCount() {
        return alignmentShiftCount;
    }

	/**
	 * Returns the array of resource types.
	 * @return the array of resource types
	 */
    public ResourceType [] getResourceTypes() {
        return types;
    }

	/**
	 * Returns the array of resources names.
	 * @return the array of resources names
	 */
    public ResourceName [] getResourceNames() {
        return names;
    }

    /**
     * Returns the byte index where the resource table begins,
     * relative to the beginning of the file.
     * @return the byte index where the resource table begins
     */
    public short getIndex() {
        return index;
    }
}
