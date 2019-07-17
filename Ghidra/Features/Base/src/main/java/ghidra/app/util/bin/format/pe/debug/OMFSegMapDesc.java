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
 * A class to represent the Object Module Format (OMF) Segment Mapping Descriptor data structure.
 * <br>
 * <pre>
 * typedef struct OMFSegMapDesc {
 *     unsigned short  flags;       // descriptor flags bit field
 *     unsigned short  ovl;         // the logical overlay number
 *     unsigned short  group;       // group index into the descriptor array
 *     unsigned short  frame;       // logical segment index - interpreted via flags
 *     unsigned short  iSegName;    // segment or group name - index into sstSegName
 *     unsigned short  iClassName;  // class name - index into sstSegName
 *     unsigned long   offset;      // byte offset of the logical within the physical segment
 *     unsigned long   cbSeg;       // byte count of the logical segment or group
 * } OMFSegMapDesc;
 * </pre>
 * 
 * 
 */
public class OMFSegMapDesc {
    final static int IMAGE_SIZEOF_OMF_SEG_MAP_DESC = 20;

    private short  flags;
    private short  ovl;
    private short  group;
    private short  frame;
    private short  iSegName;
    private short  iClassName;
    private int    offset;
    private int    cbSeg;

    static OMFSegMapDesc createOMFSegMapDesc(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFSegMapDesc omfSegMapDesc = (OMFSegMapDesc) reader.getFactory().create(OMFSegMapDesc.class);
        omfSegMapDesc.initOMFSegMapDesc(reader, ptr);
        return omfSegMapDesc;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSegMapDesc() {}

    private void initOMFSegMapDesc(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        flags      = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        ovl        = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        group      = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        frame      = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        iSegName   = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        iClassName = reader.readShort(ptr); ptr+=BinaryReader.SIZEOF_SHORT;
        offset     = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
        cbSeg      = reader.readInt  (ptr); ptr+=BinaryReader.SIZEOF_INT;
    }

	/**
	 * Returns the descriptor flags bit field.
	 * @return the descriptor flags bit field
	 */
    public short getFlags() {
        return flags;
    }
    /**
     * Returns the logical overlay number.
     * @return the logical overlay number
     */
    public short getLogicalOverlayNumber() {
        return ovl;
    }
    /**
     * Returns the group index into the descriptor array.
     * @return the group index into the descriptor array
     */
    public short getGroupIndex() {
        return group;
    }
    /**
     * Returns the logical segment index - interpreted via flags.
     * @return the logical segment index - interpreted via flags
     */
    public short getLogicalSegmentIndex() {
        return frame;
    }
    /**
     * Returns the segment or group name - index into sstSegName.
     * @return the segment or group name - index into sstSegName
     */
    public short getSegmentName() {
        return iSegName;
    }
    /**
     * Returns the class name - index into sstSegName.
     * @return the class name - index into sstSegName
     */
    public short getClassName() {
        return iClassName;
    }
    /**
     * Returns the byte offset of the logical within the physical segment.
     * @return the byte offset of the logical within the physical segment
     */
    public int getByteOffset() {
        return offset;
    }
    /**
     * Returns the byte count of the logical segment or group.
     * @return the byte count of the logical segment or group
     */
    public int getByteCount() {
        return cbSeg;
    }
}
