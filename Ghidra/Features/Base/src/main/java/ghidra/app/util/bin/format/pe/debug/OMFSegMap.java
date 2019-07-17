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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;

import java.io.*;

/**
 * <pre>
 * typedef struct OMFSegMap {
 *     unsigned short  cSeg;        // total number of segment descriptors
 *     unsigned short  cSegLog;     // number of logical segment descriptors
 *     OMFSegMapDesc   rgDesc[0];   // array of segment descriptors
 * };
 * </pre>
 * 
 * 
 */
public class OMFSegMap {
    private short cSeg;
    private short cSegLog;
    private OMFSegMapDesc [] segmentMapDesc;

    static OMFSegMap createOMFSegMap(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFSegMap omfSegMap = (OMFSegMap) reader.getFactory().create(OMFSegMap.class);
        omfSegMap.initOMFSegMap(reader, ptr);
        return omfSegMap;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSegMap() {}

    private void initOMFSegMap(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        cSeg    = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        cSegLog = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        segmentMapDesc = new OMFSegMapDesc[cSeg];
        for (int i = 0 ; i < cSeg ; ++i) {
            segmentMapDesc[i] = OMFSegMapDesc.createOMFSegMapDesc(reader, ptr);
            ptr += OMFSegMapDesc.IMAGE_SIZEOF_OMF_SEG_MAP_DESC;
        }
    }

	/**
	 * Returns the total number of segment descriptors.
	 * @return the total number of segment descriptors
	 */
    public short getSegmentDescriptorCount() {
        return cSeg;
    }
    /**
     * Returns the number of logical segment descriptors.
     * @return the number of logical segment descriptors
     */
    public short getLogicalSegmentDescriptorCount() {
        return cSegLog;
    }
    /**
     * Returns the array of segment descriptors.
     * @return the array of segment descriptors
     */
    public OMFSegMapDesc [] getSegmentDescriptor() {
        return segmentMapDesc;
    }
}
