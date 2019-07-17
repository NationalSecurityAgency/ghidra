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

public class ShortLongIndexedListTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public ShortLongIndexedListTest() {
		super();
	}

@Test
    public void testShortLongIndexedList() {

        ShortLongIndexedList ilist = new ShortLongIndexedList((short)7);

        System.out.println("Test add to list 0");
        ilist.add((short)0,20l);
        ilist.add((short)0,10l);
        ilist.add((short)0,0l);
        expect(ilist,(short)0, new long[] {0l,10l,20l}, "Add: ");

        System.out.println("Test append");
        ilist.append((short)6,30l);
        ilist.append((short)6,40l);
        ilist.append((short)6,50l);
        expect(ilist,(short)0, new long[] {0l,10l,20l}, "Add: ");
        expect(ilist, (short)6, new long[] {30l,40l,50l}, "Append");


        System.out.println("Test contains");
        if (!ilist.contains((short)0,0l)) {
            Assert.fail("list 0 does not contain 0, but it should");
        }
        if (!ilist.contains((short)0,10l)) {
            Assert.fail("list 0 does not contain 10, but it should");
        }
        if (!ilist.contains((short)0,20l)) {
            Assert.fail("list 0 does not contain 20, but it should");
        }
        if (ilist.contains((short)0,30l)) {
            Assert.fail("list 0 contains 30, but it should not");
        }
        if (ilist.contains((short)1,50l)) {
            Assert.fail("list 1 contains 50, but it should not");
        }
        if (!ilist.contains((short)6,50l)) {
            Assert.fail("list 6 does not contain 50, but it should");
        }

        System.out.println("Test remove");
        ilist.remove((short)0,0l);
        ilist.remove((short)6,50l);
        expect(ilist,(short)0, new long[] {10l,20l}, "Remove ");
        expect(ilist, (short)6, new long[] {30l,40l}, "Remove ");

        System.out.println("Test removeAll");
        ilist.removeAll((short)0);
        expect(ilist,(short)0,new long[]{},"RemoveAll ");
        expect(ilist,(short)1,new long[]{},"RemoveAll ");
        expect(ilist,(short)6,new long[]{30,40},"RemoveAll ");



        System.out.println("Test add after removeAll");
        ilist.add((short)0,100l);
        ilist.add((short)0,200l);
        ilist.add((short)0,300l);
        expect(ilist,(short)0,new long[]{300l,200l,100l}, "Add after removeAll");

        ilist.removeAll((short)0);
        ilist.removeAll((short)6);
        System.out.println("Test growing the number of lists");
        for(short i=0;i<ilist.getNumLists();i++) {
            for(long j=0;j<10;j++) {
                ilist.append(i,j);
            }
        }

        ilist.growNumLists((short)13);
        for(short i=0;i<13;i++) {
            if (i < 7) {
                expect(ilist,i,new long[]{0,1,2,3,4,5,6,7,8,9}, "Grow lists ");
            }
            else {
                expect(ilist,i,new long[]{},"Grow Lists ");
            }
        }
    }// end doTest()

    public static void expect(ShortLongIndexedList ilist, short listId, long[] values, String test) {

        long[] listValues = ilist.get(listId);
        if (values.length != listValues.length) {
            Assert.fail(test + " expected list "+listId+ "to be of length "+
                    values.length + ", but instead it was of length "+listValues.length);
        }
        for(int i=0;i<listValues.length;i++) {
            if (listValues[i] != values[i]) {
                Assert.fail(test + "list["+listId+"], item "+i+
                    "should contain "+values[i]+", but instead contains "+listValues[i]);
            }
        }
    }
}
