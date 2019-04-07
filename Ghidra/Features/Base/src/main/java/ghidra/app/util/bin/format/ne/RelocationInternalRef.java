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

import ghidra.app.util.bin.BinaryReader;

class RelocationInternalRef {
    private byte  segment;  //segment number for fixed, 0xff for moveable
    private byte  zeropad;  //padding
    private short offset;   //offset into segment if fixed segment
                            //ordinal number into entry table if moveable segment

    RelocationInternalRef(BinaryReader reader) throws IOException {
        segment  = reader.readNextByte();
        zeropad  = reader.readNextByte();
        offset   = reader.readNextShort();
    }

    public boolean isMoveable() {
        return segment == 0xff;
    }
    public byte getSegment() {
        return segment;
    }
    public byte getPad() {
        return zeropad;
    }
    public short getOffset() {
        return offset;
    }
}
