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

/**
 * A class to represent a new-executable segment relocation.
 * 
 */
public class SegmentRelocation {
	
	public final static int VALUES_SIZE = 5;
	
	/**Moveable relocation.*/
    public final static short MOVEABLE = 0xff;
    /**A mask indicating that the low-order nibble is the type.*/
    public final static byte TYPE_MASK            = 0x0f;
    /**low byte at the specified address.*/
    public final static byte TYPE_LO_BYTE         = 0x00;
    /**16-bit selector.*/
    public final static byte TYPE_SEGMENT         = 0x02;
    /**32-bit pointer.*/
    public final static byte TYPE_FAR_ADDR        = 0x03;
    /**16-bit pointer.*/
    public final static byte TYPE_OFFSET          = 0x05;
    /**48-bit pointer.*/
    public final static byte TYPE_FAR_ADDR_48     = 0x0c;
    /**32-bit offset.*/
    public final static byte TYPE_OFFSET_32       = 0x0d;
	/**The names of the available relocations.*/
    public final static String [] TYPE_STRINGS = {
                        "Low Byte",
                        "???1",
                        "16-bit Segment Selector",
                        "32-bit Pointer",
                        "???4",
                        "16-bit Pointer",
                        "???6",
                        "???7",
                        "???8",
                        "???9",
                        "???10",
                        "48-bit Pointer",
                        "???12",
                        "32-bit Offset"
    };
    /**The number of bytes required to perform relocation*/
    public final static int[] TYPE_LENGTHS = {
    					1,	// TYPE_LO_BYTE
    					0,
    					2,	// TYPE_SEGMENT
    					4,	// TYPE_FAR_ADDR
    					0,
    					2,	// TYPE_OFFSET
    					0,
    					0,
    					0,
    					0,
    					0,
    					0,
    					6,	// TYPE_FAR_ADDR_48
    					4	// TYPE_OFFSET_32
    };
    /**A mask indicating that the low-order two-bits is the type.*/
    public final static byte FLAG_TARGET_MASK     = 0x03;
    /**Internal reference relocation.*/
    public final static byte FLAG_INTERNAL_REF    = 0x00;
    /**Import ordinal relocation.*/
    public final static byte FLAG_IMPORT_ORDINAL  = 0x01;
    /**Import name relocation.*/
    public final static byte FLAG_IMPORT_NAME     = 0x02;
    /**Operating system fixup relocation.*/
    public final static byte FLAG_OS_FIXUP        = 0x03;
    /**Additive relocaiton.*/
    public final static byte FLAG_ADDITIVE        = 0x04;

    private int    segment;
    private byte   type;
    private byte   flagbyte;
    private short  offset;
    private short  targetSegment;
    private short  targetOffset;

	/**
	 * Constucts a new segment relocation.
	 * @param reader the binary reader
	 */
    SegmentRelocation(FactoryBundledWithBinaryReader reader, int segment) throws IOException {
    	this.segment  = segment;
        type          = reader.readNextByte();
        flagbyte      = reader.readNextByte();
        offset        = reader.readNextShort();
        targetSegment = reader.readNextShort();
        targetOffset  = reader.readNextShort();
    }
    
    SegmentRelocation(byte type, long[] values) {
    	this.type = type;
		if (values.length != VALUES_SIZE) {
    		throw new IllegalArgumentException("Expected " + VALUES_SIZE + " values");
    	}
    	segment = (int)values[0];
    	flagbyte = (byte)values[1];
    	offset = (short)values[2];
    	targetSegment = (short)values[3];
    	targetOffset = (short)values[4];
    }
    
    /**
     * Returns true if this relocation is an internal reference.
     * @return true if this relocation is an internal reference
     */
    public boolean isInternalRef() {
        return (flagbyte&FLAG_TARGET_MASK)==FLAG_INTERNAL_REF;
    }
	/**
	 * Returns true if this relocation is an import by ordinal.
	 * @return true if this relocation is an import by ordinal
	 */
    public boolean isImportOrdinal() {
        return (flagbyte&FLAG_TARGET_MASK)==FLAG_IMPORT_ORDINAL;
    }
	/**
	 * Returns true if this relocation is an import by name.
	 * @return true if this relocation is an import by name
	 */
    public boolean isImportName() {
        return (flagbyte&FLAG_TARGET_MASK)==FLAG_IMPORT_NAME;
    }
	/**
	 * Returns true if this relocation is an operating system fixup.
	 * @return true if this relocation is an operating system fixup
	 */
    public boolean isOpSysFixup() {
        return (flagbyte&FLAG_TARGET_MASK)==FLAG_OS_FIXUP;
    }
	/**
	 * Returns true if this relocation is additive.
	 * If this bit is set, then add relocation to existing value.
     * Otherwise overwrite the existing value.
	 * @return true if this relocation is additive.
	 */
    public boolean isAdditive() {
        return (flagbyte&FLAG_ADDITIVE)!=0;
    }
    /**
     * Returns the relocation type.
     * @return the relocation type
     */
    public byte getType() {
        return type;
    }
    /**
     * Returns the relocation flags.
     * @return the relocation flags
     */
    public byte getFlagByte() {
        return flagbyte;
    }
    /**
     * Returns the relocation offset.
     * @return the relocation offset
     */
    public short getOffset() {
        return offset;
    }
    /**
     * Returns the relocation target segment.
     * @return the relocation target segment
     */
    public short getTargetSegment() {
        return targetSegment;
    }
	/**
	 * Returns the relocation target offset.
	 * @return the relocation target offset
	 */
    public short getTargetOffset() {
        return targetOffset;
    }
    /**
     * Returns values required to reconstruct this object.
     * @return values required to reconstruct this object
     */
    public long[] getValues() {
    	return new long[] {
    			segment, flagbyte, offset, targetSegment, targetOffset
    	};
    }
}
