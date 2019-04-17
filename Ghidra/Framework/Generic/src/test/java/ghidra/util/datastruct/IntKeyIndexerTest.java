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
import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class IntKeyIndexerTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public IntKeyIndexerTest() {
		super();
	}

@Test
    public void testIntKeyIndexer() {

        IntKeyIndexer indexer = new IntKeyIndexer(13);

        System.out.println("Test put method");
        int index;

        index = indexer.put(1000);
        if (index != 0) {
            Assert.fail("Put: expected 0, got "+index);
        }
        index = indexer.put(2000);
        if (index != 1) {
            Assert.fail("Put: expected 1, got "+index);
        }
        index = indexer.put(3000);
        if (index != 2) {
            Assert.fail("Put: expected 2, got "+index);
        }
        index = indexer.put(4000);
        if (index != 3) {
            Assert.fail("Put: expected 3, got "+index);
        }
        index = indexer.put(123);
        if (index != 4) {
            Assert.fail("Put: expected 4, got "+index);
        }
        index = indexer.put(456);
        if (index != 5) {
            Assert.fail("Put: expected 5, got "+index);
        }
        index = indexer.put(1789);
        if (index != 6) {
            Assert.fail("Put: expected 6, got "+index);
        }
        index = indexer.put(2000);
        if (index != 1) {
            Assert.fail("Put: expected 1, got "+index);
        }

        System.out.println("Test remove method");

        indexer.remove(4000);
        index = indexer.get(4000);
        if (index != -1) {
            Assert.fail("Expected to get -1 on remove of " +
                "non-existent index and instead got "+index);
        }
        index = indexer.put(9999);
        if (index != 3) {
            Assert.fail("Remove: expected 3, got "+index);
        }


        System.out.println("Test grow");

        for(int i=0;i<20;i++) {
            indexer.put(i);
        }
        index = indexer.get(1000);
        if (index != 0) {
            Assert.fail("Grow: expected 0, got "+index);
        }
        index = indexer.get(2000);
        if (index != 1) {
            Assert.fail("Grow: expected 1, got "+index);
        }
        index = indexer.get(3000);
        if (index != 2) {
            Assert.fail("Grow: expected 2, got "+index);
        }
        index = indexer.get(4000);
        if (index != -1) {
            Assert.fail("Grow: expected 3, got "+index);
        }
        index = indexer.get(123);
        if (index != 4) {
            Assert.fail("Grow: expected 4, got "+index);
        }
        index = indexer.get(456);
        if (index != 5) {
            Assert.fail("Grow: expected 5, got "+index);
        }
        index = indexer.get(1789);
        if (index != 6) {
            Assert.fail("Grow: expected 6, got "+index);
        }
        index = indexer.get(0);
        if (index != 7) {
            Assert.fail("Grow: expected 7, got "+index);
        }

        index = indexer.get(500);
        if (index != -1) {
            Assert.fail("Grow: expected -1, got "+index);
        }

        System.out.println("Test capacity");
        if (indexer.getCapacity() != 37) {
            Assert.fail("Capacity should be 37, but it is "+indexer.getCapacity());
        }

        indexer.clear();
        for(int i=0;i<100;i++) {
            indexer.put(i);
        }
        for(int i=0;i<100;i++) {
            if (indexer.get(i) != i) {
                Assert.fail("Sequence: expected "+i+", and got"+indexer.get(i));
            }
        }

    }//end doTest()

}
