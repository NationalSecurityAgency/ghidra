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

import java.io.IOException;

import ghidra.app.util.bin.format.*;

/**
 * A class to represent a new-executable entry point.
 * 
 * 
 */
public class EntryPoint {
	public final static byte EXPORTED = (byte) 0x01;
	public final static byte GLOBAL   = (byte) 0x02;

    private byte   flagword;
    private short  instruction; //an int 0x3f__ instruction
    private byte   segment;     //segment number
    private short  offset;      //within segment to entry point

    private EntryTableBundle etb;

    /**
     * Constructs a new entry point given a binary reader
     * and an entry table bundle.
     * 
     * @param reader the binary reader
     * @param etb the entry table bundle
     */
    EntryPoint(FactoryBundledWithBinaryReader reader, EntryTableBundle etb) throws IOException {
        this.etb = etb;

        flagword = reader.readNextByte();
        if (etb.isMoveable()) {
            instruction = reader.readNextShort();
            segment     = reader.readNextByte();
        }
        offset = reader.readNextShort();
    }

    /**
     * Returns the flagword.
     * @return the flagword
     */
    public byte getFlagword() {
        return flagword;
    }

    /**
     * Returns the instruction.
     * @return the instruction
     */
    public short getInstruction() {
        if (!etb.isMoveable()) {
            throw new RuntimeException("Entry point is not moveable!");
        }
        return instruction;
    }

    /**
     * Returns the segment.
     * @return the segment
     */
    public byte getSegment() {
        if (!etb.isMoveable()) {
            throw new RuntimeException("Entry point is not moveable!");
        }
        return segment;
    }

    /**
     * Returns the offset.
     * @return the offset
     */
    public short getOffset() {
        return offset;
    }
}
