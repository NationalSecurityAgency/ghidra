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

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;

import java.io.*;

/**
 * A class to represent the Object Module Format (OMF) Segment Descriptor data structure.
 * Information describing each segment in a module.
 * <br>
 * <pre>
 * typedef struct OMFSegDesc {
 *     unsigned short  Seg;            // segment index
 *     unsigned short  pad;            // pad to maintain alignment
 *     unsigned long   Off;            // offset of code in segment
 *     unsigned long   cbSeg;          // number of bytes in segment
 * } OMFSegDesc;
 * </pre>
 * 
 * 
 */
public class OMFSegDesc {
    final static int IMAGE_SIZEOF_OMF_SEG_DESC = 12;

    private short seg;
    private short pad;
    private int   offset;
    private int   cbSeg;

    static OMFSegDesc createOMFSegDesc(
            FactoryBundledWithBinaryReader reader, int index)
            throws IOException {
        OMFSegDesc omfSegDesc = (OMFSegDesc) reader.getFactory().create(OMFSegDesc.class);
        omfSegDesc.initOMFSegDesc(reader, index);
        return omfSegDesc;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSegDesc() {}

    private void initOMFSegDesc(FactoryBundledWithBinaryReader reader, int index) throws IOException {
        seg    = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        pad    = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        offset = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
        cbSeg  = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
    }

	/**
	 * Returns the segment index.
	 * @return the segment index
	 */
    public short getSegmentIndex() {
        return seg;
    }
    /**
     * Returns the pad to maintain alignment.
     * @return the pad to maintain alignment
     */
    public short getAlignmentPad() {
        return pad;
    }
    /**
     * Returns the offset of code in segment.
     * @return the offset of code in segment
     */
    public int getOffset() {
        return offset;
    }
    /**
     * Returns the number of bytes in segment.
     * @return the number of bytes in segment
     */
    public int getNumberOfBytes() {
        return cbSeg;
    }
}
