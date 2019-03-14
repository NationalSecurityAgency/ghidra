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
package ghidra.util.datastruct;
import java.io.Serializable;
import java.util.ArrayList;


/**
 * Class to generate short indexes to be used for arrays or tables.  If a location
 * or entry in a table becomes available, the index for that location is released.
 * This class manages the use and reuse of those indexes.
 */
public class ShortIndexManager implements Serializable {
    private final static long serialVersionUID = 1;

    private short nextIndex;        // the smallest index that has never been used.
    private ArrayList<Short> freeList;

    /**
     * Constructs an ShortIndexManager.
     */
    public ShortIndexManager() {
        nextIndex = 0;
        freeList = new ArrayList<Short>();
    }

    /**
     * Returns the smallest unused index value.
     * @exception IndexOutOfBoundsException thrown if there are no unused
     * indexes.
     */
    public short allocate() {
        if (freeList.size() == 0) {
            if (nextIndex < 0) {
                throw new IndexOutOfBoundsException();
            }
            short temp = nextIndex;
            nextIndex++;
            return temp;
        }
        Short s = freeList.remove(freeList.size()-1);
        return s.shortValue();
    }

    /**
     * Returns the index value so that it can be reused.
     * @param index the index to be free'd for reuse.
     */
    public void deallocate(short index) {
        if ((index < 0) || (index >= nextIndex)) {
            throw new IndexOutOfBoundsException();
        }

        if (index == nextIndex-1) {
            nextIndex--;
        }
        else {
            freeList.add(new Short(index));
        }

        // all nodes are free, so reset...
        if (nextIndex == freeList.size()) {
            clear();
        }
    }

    /**
     * frees all index values.
     */
    public void clear() {
        nextIndex = 0;
        freeList.clear();
    }
}
