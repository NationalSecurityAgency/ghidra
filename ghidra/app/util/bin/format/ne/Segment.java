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

import ghidra.app.util.bin.format.*;
import ghidra.util.Conv;

import java.io.IOException;
import java.util.ArrayList;

/**
 * A class to represent a new-executable segment.
 * 
 * 
 */
public class Segment {
	/**data segment type.*/
    private final static short FLAG_DATA       = (short) 0x0001;
    /**loaded has allocated memory.*/
    private final static short FLAG_ALLOC      = (short) 0x0002;
    /**segment is loaded.*/
    private final static short FLAG_LOADED     = (short) 0x0004;
    /**segment not fixed.*/
    private final static short FLAG_MOVEABLE   = (short) 0x0010;
    /**pure (shareable) or impure (unshareable).*/
    private final static short FLAG_PURE       = (short) 0x0020;
    /**preload or load-on-call.*/
    private final static short FLAG_PRELOAD    = (short) 0x0040;
    /**if code, segment is execute-only.*/
    private final static short FLAG_EXE_ONLY   = (short) 0x0080;
    /**if data, segment is read-only.*/
    private final static short FLAG_READ_ONLY  = (short) 0x0080;
    /**segment has relocation records.*/
    private final static short FLAG_RELOC_INFO = (short) 0x0100;
    /**segment is discardable.*/
    private final static short FLAG_DISCARD    = (short) 0x1000;
    /**segment is 32 bit */
    private final static short FLAG_32BIT      = (short) 0x2000;

    private FactoryBundledWithBinaryReader reader;
    private int segmentID;
    private short offset;       //byte offset to content, relative to BOF (zero means no file data)
    private short length;       //length of segment in file (zero means 64k)
    private short flagword;     //flags
    private short minAllocSize; //minimum size in memory to allocate (zero means 64k)
    private int   offsetAlign;  //the aligned offset value
    private short nRelocations; //number of relocations
    private SegmentRelocation [] relocations; //relocation records

    Segment(FactoryBundledWithBinaryReader reader, short segmentAlignment, int segmentID) throws IOException {
        this.reader = reader;
        this.segmentID = segmentID;
        
        offset       = reader.readNextShort();
        length       = reader.readNextShort();
        flagword     = reader.readNextShort();
        minAllocSize = reader.readNextShort();

        offsetAlign  = Conv.shortToInt(offset) * Conv.shortToInt(segmentAlignment);

        ArrayList<SegmentRelocation> list = new ArrayList<SegmentRelocation>();
        if (hasRelocation()) {
            int relocPos = offsetAlign + Conv.shortToInt(length);

            long oldIndex = reader.getPointerIndex();
            reader.setPointerIndex(relocPos);

            nRelocations = reader.readNextShort();

            for (short i = 0 ; i < nRelocations ; ++i) {
                list.add(new SegmentRelocation(reader, segmentID));
            }
            reader.setPointerIndex(oldIndex);
        }
        relocations = new SegmentRelocation[list.size()];
        list.toArray(relocations);
    }
    
    /**
     * Returns segment ID.
     * @return segment ID
     */
    public int getSegmentID() {
    	return segmentID;
    }

    /**
     * Returns true if the segment should operate in 32 bit mode.
     * @return true if the segment should operate in 32 bit mode
     */
    public boolean is32bit() {
    	return (flagword & FLAG_32BIT) != 0;
    }
	/**
	 * Returns true if this is a code segment.
	 * @return true if this is a code segment
	 */
    public boolean isCode() {
        return !isData();
    }
    /**
     * Returns true if this is a data segment.
     * @return true if this is a data segment
     */
    public boolean isData() {
        return (flagword & FLAG_DATA) != 0;
    }
    /**
     * Returns true if this segment has relocations.
     * @return true if this segment has relocations
     */
    public boolean hasRelocation() {
        return (flagword & FLAG_RELOC_INFO) != 0;
    }
    /**
     * Returns true if this segment is loader allocated.
     * @return true if this segment is loader allocated
     */
    public boolean isLoaderAllocated() {
        return (flagword & FLAG_ALLOC) != 0;
    }
    /**
     * Returns true if this segment is loaded.
     * @return true if this segment is loaded
     */
    public boolean isLoaded() {
        return (flagword & FLAG_LOADED) != 0;
    }
    /**
     * Returns true if this segment is moveable.
     * @return true if this segment is moveable
     */
    public boolean isMoveable() {
        return (flagword & FLAG_MOVEABLE) != 0;
    }
	/**
	 * Returns true if this segment is preloaded.
	 * @return true if this segment is preloaded
	 */
    public boolean isPreload() {
        return (flagword & FLAG_PRELOAD) != 0;
    }
	/**
	 * Returns true if this segment is pure.
	 * @return true if this segment is pure
	 */
    public boolean isPure() {
        return (flagword & FLAG_PURE) != 0;
    }
	/**
	 * Returns true if this segment is read-only.
	 * @return true if this segment is read-only
	 */
    public boolean isReadOnly() {
        return isData() && (flagword & FLAG_READ_ONLY) != 0;
    }
	/**
	 * Returns true if this segment is execute-only.
	 * @return true if this segment is execute-only
	 */
    public boolean isExecuteOnly() {
        return isCode() && (flagword & FLAG_EXE_ONLY) != 0;
    }
	/**
	 * Returns true if this segment is discardable.
	 * @return true if this segment is discardable
	 */
    public boolean isDiscardable() {
        return (flagword & FLAG_DISCARD) != 0;
    }
    /**
     * Returns the flag word of this segment.
     * @return the flag word of this segment
     */
    public short getFlagword(){
        return flagword;
    }
    /**
     * Returns the length of this segment.
     * @return the length of this segment
     */
    public short getLength() {
        return length;
    }
    /**
     * Returns the minimum allocation size of this segment.
     * @return the minimum allocation size of this segment
     */
    public short getMinAllocSize() {
        return minAllocSize;
    }
    /**
     * Returns the offset to the contents of this segment. 
     * NOTE: This value needs to be shift aligned.
     * @return the offset to the contents of this segment
     */
    public short getOffset() {
        return offset;
    }
    /**
     * Returns the actual (shifted) offset to the contents.
     * @return the actual (shifted) offset to the contents
     */
    public int getOffsetShiftAligned() {
        return offsetAlign;
    }
    /**
     * Returns an array of the relocations defined for this segment.
     * @return an array of the relocations defined for this segment
     */
    public SegmentRelocation [] getRelocations() {
        return relocations;
    }
    /**
     * Returns the bytes the comprise this segment.
     * The size of the byte array is MAX(length,minalloc).
     * @return the bytes the comprise this segment
     */
    public byte [] getBytes() throws IOException {
        int   offset_int = getOffsetShiftAligned();
        int   length_int = Conv.shortToInt(getLength());
        int minalloc_int = Conv.shortToInt(getMinAllocSize());

        if (minalloc_int == 0) minalloc_int = 0x10000;

        byte [] bytes = reader.readByteArray(offset_int, length_int);

        if (length_int >= minalloc_int) {
            return bytes;
        }
        byte [] newbytes = new byte[minalloc_int];
        System.arraycopy(bytes, 0, newbytes, 0, length_int);
        return newbytes;
    }
}
