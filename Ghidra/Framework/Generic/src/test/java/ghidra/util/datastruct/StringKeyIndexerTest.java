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
package ghidra.util.datastruct;
import java.util.HashSet;
import java.util.Iterator;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class StringKeyIndexerTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public StringKeyIndexerTest() {
		super();
	}

@Test
    public void testStringKeyIndexer() {

        StringKeyIndexer indexer = new StringKeyIndexer(13);

        System.out.println("Test put method");
        int index;

        index = indexer.put("A");
        if (index != 0) {
            Assert.fail("Put: expected 0, got "+index);
        }
        index = indexer.put("B");
        if (index != 1) {
            Assert.fail("Put: expected 1, got "+index);
        }
        index = indexer.put("C");
        if (index != 2) {
            Assert.fail("Put: expected 2, got "+index);
        }
        index = indexer.put("D");
        if (index != 3) {
            Assert.fail("Put: expected 3, got "+index);
        }
        index = indexer.put("E");
        if (index != 4) {
            Assert.fail("Put: expected 4, got "+index);
        }
        index = indexer.put("F");
        if (index != 5) {
            Assert.fail("Put: expected 5, got "+index);
        }
        index = indexer.put("G");
        if (index != 6) {
            Assert.fail("Put: expected 6, got "+index);
        }
        index = indexer.put("B");
        if (index != 1) {
            Assert.fail("Put: expected 1, got "+index);
        }

        System.out.println("Test remove method");

        indexer.remove("D");
        index = indexer.get("D");
        if (index != -1) {
            Assert.fail("Expected to get -1 on remove of " +
                "non-existent index and instead got "+index);
        }
        index = indexer.put("Z");
        if (index != 3) {
            Assert.fail("Remove: expected 3, got "+index);
        }


        System.out.println("Test grow");

        for(int i=0;i<20;i++) {
            indexer.put("LAB"+i);
        }
        index = indexer.get("A");
        if (index != 0) {
            Assert.fail("Grow: expected 0, got "+index);
        }
        index = indexer.get("B");
        if (index != 1) {
            Assert.fail("Grow: expected 1, got "+index);
        }
        index = indexer.get("C");
        if (index != 2) {
            Assert.fail("Grow: expected 2, got "+index);
        }
        index = indexer.get("D");
        if (index != -1) {
            Assert.fail("Grow: expected 3, got "+index);
        }
        index = indexer.get("E");
        if (index != 4) {
            Assert.fail("Grow: expected 4, got "+index);
        }
        index = indexer.get("F");
        if (index != 5) {
            Assert.fail("Grow: expected 5, got "+index);
        }
        index = indexer.get("G");
        if (index != 6) {
            Assert.fail("Grow: expected 6, got "+index);
        }
        index = indexer.get("LAB"+0);
        if (index != 7) {
            Assert.fail("Grow: expected 7, got "+index);
        }

        index = indexer.get("M");
        if (index != -1) {
            Assert.fail("Grow: expected -1, got "+index);
        }

        System.out.println("Test capacity");
        if (indexer.getCapacity() != 37) {
            Assert.fail("Capacity should be 37, but it is "+indexer.getCapacity());
        }

        indexer.clear();
        for(int i=0;i<100;i++) {
            indexer.put("LAB"+i);
        }
        for(int i=0;i<100;i++) {
            if (indexer.get("LAB"+i) != i) {
                Assert.fail("Sequence: expected "+i+", and got"+indexer.get("LAB"+i));
            }
        }

        System.out.println("Test getKeys()");

        String[] keys = indexer.getKeys();
        HashSet<String> hashSet = new HashSet<String>();
        for(int i=0;i<100;i++) {
        	hashSet.add(keys[i]);
        }

        if (keys.length != 100) {
        	Assert.fail("Expeced keys to be length 100 and got "+keys.length);
        }
        for(int i=0;i<100;i++) {
            if (!hashSet.contains(keys[i])) {
                Assert.fail("1 Expected set to contain "+keys[i]+ " and it doesn't");
            }
            hashSet.remove(keys[i]);
        }

        System.out.println("Test getKeyIterator");

        for(int i=0;i<100;i++) {
        	hashSet.add(keys[i]);
        }
        Iterator<?> it = indexer.getKeyIterator();

        while (it.hasNext()) {

            String key = (String)it.next();
            if (!hashSet.contains(key)) {
                Assert.fail("Expected set to contain "+key+ " and it doesn't");
            }
            hashSet.remove(key);
        }
        if (hashSet.size() != 0) {
            Assert.fail("Expeced iterator to contain 100 Keys and got "+(100 - hashSet.size()));
        }


    }//end doTest()

}
