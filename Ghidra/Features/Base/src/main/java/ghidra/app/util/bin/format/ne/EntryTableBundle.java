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
import ghidra.util.Conv;

/**
 * A class to represent a new-executable entry table bundle.
 * 
 * 
 */
public class EntryTableBundle {
    /**
     * Marker denoting an unused entry table bundle.
     */
    public final static byte UNUSED = 0x00;
    /**
     * Segment is moveable.
     */
    public final static byte MOVEABLE = (byte) 0xff;
    /**
     * Refers to a constant defined in module.
     */
    public final static byte CONSTANT = (byte) 0xfe;

    private byte count;
    private byte type;

    private EntryPoint [] entryPoints;

    /**
     * Constructs a new entry table bundle.
     * @param reader the binary reader
     */
    EntryTableBundle(FactoryBundledWithBinaryReader reader) throws IOException {
        count = reader.readNextByte();
        if (count == 0) return; //do not read anymore data...

        type = reader.readNextByte();
        if (type == 0) return; //unused bundle...

        int count_int = Conv.byteToInt(count);

        entryPoints = new EntryPoint[count_int];
        for (int i = 0 ; i < count_int ; ++i) {
            entryPoints[i] = new EntryPoint(reader, this);
        }
    }

    /**
     * Returns true if this bundle is moveable.
     * @return true if this bundle is moveable
     */
    public boolean isMoveable() {
        return type == MOVEABLE;
    }

    /**
     * Returns true if this bundle is constant.
     * @return true if this bundle is constant
     */
    public boolean isConstant() {
        return type == CONSTANT;
    }

    /**
     * Returns the number of entries in bundle.
     * @return the number of entries in bundle
     */
    public byte getCount() {
        return count;
    }

    /**
     * Returns the type of the bundle. For example,
     * MOVEABLE, CONSTANT, or segment index.
     * 
     * @return the type of the bundle
     */
    public byte getType() {
        return type;
    }

    /**
     * Returns the array of entry points in this bundle.
     * @return the array of entry points in this bundle
     */
    public EntryPoint [] getEntryPoints() {
        return entryPoints;
    }
}
