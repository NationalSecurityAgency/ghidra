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

public class ShortListIndexerTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public ShortListIndexerTest() {
		super();
	}

@Test
    public void testShortListIndexer() {

        ShortListIndexer indexer = new ShortListIndexer((short)5, (short)13);

        System.out.println("Test adding to some lists");

        indexer.add((short)1);
        indexer.add((short)1);
        indexer.add((short)1);
        indexer.add((short)0);
        indexer.add((short)0);
        indexer.add((short)1);
        indexer.add((short)1);
        System.out.println("Expect list 0 to contain 4,3 and list 1 to contain 6,5,2,1,0");
        System.out.println("and all others to be empty.");
        System.out.println("list 1 contains "+indexer.getListSize((short)1)+ "items");
        expect(indexer, 0, new short[]{ 4, 3}, "Adding elements");
        expect(indexer, 1, new short[]{6,5,2,1,0}, "Adding elements");
        expect(indexer, 2, new short[]{}, "Adding elements");
        expect(indexer, 3, new short[]{}, "Adding elements");
        expect(indexer, 4, new short[]{}, "Adding elements");

        System.out.println("Test delete");
        indexer.remove((short)1,(short)2);
        indexer.remove((short)1,(short)1);
        indexer.add((short)4);
        indexer.add((short)4);
        indexer.add((short)4);
        expect(indexer, 0, new short[]{4, 3}, "Deleting elements");
        expect(indexer, 1, new short[]{6,5,0}, "Deleting elements");
        expect(indexer, 2, new short[]{}, "Deleting elements");
        expect(indexer, 3, new short[]{}, "Deleting elements");
        expect(indexer, 4, new short[]{7,2,1}, "Deleting elements");


        System.out.println("Test removeAll");
        indexer.removeAll((short)0);
        expect(indexer, 0, new short[]{}, "Deleting elements");
        expect(indexer, 1, new short[]{6,5,0}, "Deleting elements");
        expect(indexer, 2, new short[]{}, "Deleting elements");
        expect(indexer, 3, new short[]{}, "Deleting elements");
        expect(indexer, 4, new short[]{7,2,1}, "Deleting elements");

        System.out.println("Test capacity");
        if (indexer.getCapacity() != (short)13) {
            Assert.fail("The capacity should be 13, but it is "+indexer.getCapacity());
        }
        System.out.println("Test numLists");
        if (indexer.getNumLists() != (short)5) {
            Assert.fail("The number of lists should be 5, but it is "+indexer.getNumLists());
        }
        System.out.println("Test size");
        if (indexer.getSize() != (short)6) {
            Assert.fail("The size should be 6, but it is "+indexer.getSize());
        }

        System.out.println("Test resize");
        indexer.growCapacity((short)17);
        indexer.growNumLists((short)9);

        System.out.println("Test capacity");
        if (indexer.getCapacity() != (short)17) {
            Assert.fail("The capacity should be 17, but it is "+indexer.getCapacity());
        }
        System.out.println("Test numLists");
        if (indexer.getNumLists() != (short)9) {
            Assert.fail("The number of lists should be 9, but it is "+indexer.getNumLists());
        }
        System.out.println("Test size");
        if (indexer.getSize() != (short)6) {
            Assert.fail("The size should be 6, but it is "+indexer.getSize());
        }
        expect(indexer, 0, new short[]{}, "resize");
        expect(indexer, 1, new short[]{6,5,0}, "resize");
        expect(indexer, 2, new short[]{}, "resize");
        expect(indexer, 3, new short[]{}, "resize");
        expect(indexer, 4, new short[]{7,2,1}, "resize");
        expect(indexer, 5, new short[]{}, "resize");
        expect(indexer, 6, new short[]{}, "resize");
        expect(indexer, 7, new short[]{}, "resize");
        expect(indexer, 8, new short[]{}, "resize");

        System.out.println("Test clear");
        indexer.clear();
        expect(indexer, 0, new short[]{}, "clear");
        expect(indexer, 1, new short[]{}, "clear");
        expect(indexer, 2, new short[]{}, "clear");
        expect(indexer, 3, new short[]{}, "clear");
        expect(indexer, 4, new short[]{}, "clear");
        expect(indexer, 5, new short[]{}, "clear");
        expect(indexer, 6, new short[]{}, "clear");
        expect(indexer, 7, new short[]{}, "clear");
        expect(indexer, 8, new short[]{}, "clear");

        System.out.println("Test capacity");
        if (indexer.getCapacity() != (short)17) {
            Assert.fail("The capacity should be 17, but it is "+indexer.getCapacity());
        }
        System.out.println("Test numLists");
        if (indexer.getNumLists() != (short)9) {
            Assert.fail("The number of lists should be 9, but it is "+indexer.getNumLists());
        }
        System.out.println("Test size");
        if (indexer.getSize() != (short)0) {
            Assert.fail("The size should be 0, but it is "+indexer.getSize());
        }


        System.out.println("Test append method");
        indexer.append((short)0);
        indexer.append((short)0);
        indexer.append((short)0);
        expect(indexer, 0, new short[]{0,1,2}, "append");
        expect(indexer, 1, new short[]{}, "append");
        expect(indexer, 2, new short[]{}, "append");
        expect(indexer, 3, new short[]{}, "append");
        expect(indexer, 4, new short[]{}, "append");
        expect(indexer, 5, new short[]{}, "append");
        expect(indexer, 6, new short[]{}, "append");
        expect(indexer, 7, new short[]{}, "append");
        expect(indexer, 8, new short[]{}, "append");

        System.out.println("Test adding to all lists");
        indexer.clear();
        for(int i=0;i<indexer.getNumLists();i++) {
            for(int j=0;j<6;j++) {
                indexer.append((short)i);
            }
        }
        expect(indexer,0,new short[]{0,1,2,3,4,5}, "Add to all lists");
        expect(indexer,1,new short[]{6,7,8,9,10,11}, "Add to all lists");
        expect(indexer,2,new short[]{12,13,14,15,16,17}, "Add to all lists");
        expect(indexer,3,new short[]{18,19,20,21,22,23}, "Add to all lists");
        expect(indexer,4,new short[]{24,25,26,27,28,29}, "Add to all lists");
        expect(indexer,5,new short[]{30,31,32,33,34,35}, "Add to all lists");
        expect(indexer,6,new short[]{36,37,38,39,40,41}, "Add to all lists");
        expect(indexer,7,new short[]{42,43,44,45,46,47}, "Add to all lists");
        expect(indexer,8,new short[]{48,49,50,51,52,53}, "Add to all lists");
    }
    
    public static void expect(ShortListIndexer indexer, int listID, short[] values, String test) {

        if (indexer.getListSize((short)listID) != values.length) {
            Assert.fail("expected list "+listID+"to contain "+values.length+
                        " values, but instead it has "+indexer.getListSize((short)listID));
        }

        int i = 0;
        short p = indexer.first((short)listID);
        while(p != -1) {
            if (p != values[i] ) {
                Assert.fail("Expected list "+listID+ " to have the value "+
                        values[i]+" at index "+i+", but it has value "+p);
            }
            i++;
            p = indexer.next(p);
        }
    }

}
