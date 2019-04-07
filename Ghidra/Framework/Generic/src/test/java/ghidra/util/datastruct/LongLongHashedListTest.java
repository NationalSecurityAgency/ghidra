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

public class LongLongHashedListTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public LongLongHashedListTest() {
		super();
	}

@Test
    public void testLongLongHashedList() {

        LongLongHashedList ilist = new LongLongHashedList(7);

        System.out.println("Test add to list 0");
        ilist.add(50000,20);
        ilist.add(50000,10);
        ilist.add(50000,0);
        expect(ilist,50000, new long[] {0,10,20}, "Add: ");

        System.out.println("Test append");
        ilist.append(6,30);
        ilist.append(6,40);
        ilist.append(6,50);
        expect(ilist,50000, new long[] {0,10,20}, "Add: ");
        expect(ilist, 6, new long[] {30,40,50}, "Append");


        System.out.println("Test contains");
        if (!ilist.contains(50000,0)) {
            Assert.fail("list 50000 does not contain 0, but it should");
        }
        if (!ilist.contains(50000,10)) {
            Assert.fail("list 50000 does not contain 10, but it should");
        }
        if (!ilist.contains(50000,20)) {
            Assert.fail("list 50000 does not contain 20, but it should");
        }
        if (ilist.contains(50000,30)) {
            Assert.fail("list 50000 contains 30, but it should not");
        }
        if (ilist.contains(1,50)) {
            Assert.fail("list 1 contains 50, but it should not");
        }
        if (!ilist.contains(6,50)) {
            Assert.fail("list 6 does not contain 50, but it should");
        }

        System.out.println("Test remove");
        ilist.remove(50000,0);
        ilist.remove(6,50);
        expect(ilist,50000, new long[] {10,20}, "Remove ");
        expect(ilist, 6, new long[] {30,40}, "Remove ");

        System.out.println("Test removeAll");
        ilist.removeAll(50000);
        expect(ilist,50000,new long[]{},"RemoveAll ");
        expect(ilist,1,new long[]{},"RemoveAll ");
        expect(ilist,6,new long[]{30,40},"RemoveAll ");



        System.out.println("Test add after removeAll");
        ilist.add(50000,100);
        ilist.add(50000,200);
        ilist.add(50000,300);
        expect(ilist,50000,new long[]{300,200,100}, "Add after removeAll");

        ilist.removeAll(50000);
        ilist.removeAll(6);

        System.out.println("Test growing the number of lists");
        for(int i = 0;i<20;i++) {
            for(int j=0;j<10;j++) {
                ilist.append(i,j);
            }
        }

    }// end doTest()

    public static void expect(LongLongHashedList ilist, long listId, long[] values, String test) {

        long[] listValues = ilist.get(listId);
        if (listValues == null) {
            listValues = new long[0];
        }
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
