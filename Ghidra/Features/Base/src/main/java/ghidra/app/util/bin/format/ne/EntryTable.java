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
 * A class to represent a new-executable entry table.
 * 
 * 
 */
public class EntryTable {
    private EntryTableBundle [] bundles;

    /**
     * Constructs a new entry table.
     * @param reader the binary reader
     * @param index the index where the entry table begins
     * @param byteCount the length in bytes of the entry table
     */
    EntryTable(FactoryBundledWithBinaryReader reader, short index, short byteCount) throws IOException {
        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(Conv.shortToInt(index));

        ArrayList<EntryTableBundle> list = new ArrayList<EntryTableBundle>();
        while (true) {
            EntryTableBundle etb = new EntryTableBundle(reader);
            if (etb.getCount() == 0) break;
            list.add(etb);
        }
        bundles = new EntryTableBundle[list.size()];
        list.toArray(bundles);

        reader.setPointerIndex(oldIndex);
    }

    /**
     * Returns an array of the entry table bundles in this
     * entry table.
     * 
     * @return an array of entry table bundles
     */
    public EntryTableBundle [] getBundles() {
        return bundles;
    }
}
