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
package ghidra.app.plugin.core.format;

import java.util.*;

/**
 * Defines a selection for byte blocks.
 */
public class ByteBlockSelection {

    private List<ByteBlockRange> list;

    /**
     * Construct an empty selection.
     */
    public ByteBlockSelection() {
        list = new ArrayList<ByteBlockRange>();
    }
    /**
     *  Constructor
     */ 
    public ByteBlockSelection(ByteBlockRange[] ranges) {
        List<ByteBlockRange> l = Arrays.asList(ranges);
        list = new ArrayList<ByteBlockRange>(l);
    }

    /**
     * Add a range to the selection.
     */
    public void add(ByteBlockRange range) {
        list.add(range);
    }

    /**
     * Get the number of byte block ranges in this selection.
     * 
     * @return int
     */
    public int getNumberOfRanges() {
        return list.size();
    }

    /**
     * Get the byte block range at the given index.
     */
    public ByteBlockRange getRange(int index) {
        return list.get(index);
    }

}
