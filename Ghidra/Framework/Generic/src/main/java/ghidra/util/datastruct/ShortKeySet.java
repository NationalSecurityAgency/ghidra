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

/**
 * The ShortKeySet provides an interface for managing a set of ordered short keys
 * between the values of 0 and N.  It can add keys, remove keys, find the next key
 * greater than some value , and find the previous key less than some value.
 */

public interface ShortKeySet {

    /**
     * Returns the number of keys currently in the set.
     */
    public int size();

    /**
     * Determines if a given key is in the set.
     * @param key the key whose presence is to be tested.
     * @return true if the key is in the set.
     */
    public boolean containsKey(short key);

    /**
     * Returns the first (lowest) key in the set.
     */
    public short getFirst();

    /**
     * Returns the last (highest) key in the set.
     */
    public short getLast();

    /**
     *  Adds a key to the set.
     * @param key the key to add to the set.
     */
    public void put(short key);

    /**
     *  Removes the key from the set.
     * @param key the key to remove from the set.
     */
    public boolean remove(short key);

    /**
     * Removes all keys from the set.
     */
    public void removeAll();

    /**
     * finds the next key that is in the set that is greater than the given key.
     * @param key the key for which to find the next key after.
     */
    public short getNext(short key);

    /**
     * finds the previous key that is in the set that is less than the given key.
     * @param key the key for which to find the previous key.
     */
    public short getPrevious(short key);

    /**
     *  Checks if the set is empty.
     * @return true if the set is empty.
     */
    public boolean isEmpty();
}
