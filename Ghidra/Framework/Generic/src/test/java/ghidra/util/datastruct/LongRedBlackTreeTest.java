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
import java.util.Iterator;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class LongRedBlackTreeTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public LongRedBlackTreeTest() {
		super();
	}

@Test
    public void testLongRedBlackTree() {

        LongRedBlackTree rbt = new LongRedBlackTree();

        System.out.println("Test put method");

        rbt.put(25, new Long(25));
        rbt.put(234, new Long(234));
        rbt.put(2,new Long(2) );
        rbt.put(999, new Long(999));
        rbt.put(0, new Long(0));
        rbt.put(700, new Long(700));

        test(rbt, 25, new Long(25));
        test(rbt,234, new Long(234));
        test(rbt,2,new Long(2) );
        test(rbt,999, new Long(999));
        test(rbt,0, new Long(0));
        test(rbt,700, new Long(700));

        System.out.println("Test atOrBefore and atOrAfter methods");

        Object obj = rbt.getAtOrBefore(600);
        if (!obj.equals(new Long(234))) {
            Assert.fail("Value at or before 600 should be 234, but was "+rbt.getAtOrBefore(600));
        }
        obj = rbt.getAtOrAfter(600);
        if (!obj.equals(new Long(700))) {
            Assert.fail("Value at or after 600 should be 700, but was "+rbt.getAtOrBefore(600));
        }
        obj = rbt.getAtOrBefore(700);
        if (!obj.equals(new Long(700))) {
            Assert.fail("Value at or before 700 should be 700, but was "+rbt.getAtOrBefore(600));
        }
        obj = rbt.getAtOrBefore(10000);
        if (!obj.equals(new Long(999))) {
            Assert.fail("Value at or before 10000 should be 999, but was "+rbt.getAtOrBefore(600));
        }


        System.out.println("Test the iterator");
        Iterator<?> it = rbt.iterator();

        Object[] objs = new Object[6];
        objs[0] = new Long(0);
        objs[1] = new Long(2);
        objs[2] = new Long(25);
        objs[3] = new Long(234);
        objs[4] = new Long(700);
        objs[5] = new Long(999);

        int i = 0;
        while(it.hasNext()) {
            Object o = it.next();
            if (!o.equals(objs[i])) {
                Assert.fail("expected "+objs[i]+" but got "+o);
            }
            i++;
        }
    }
    public static void test(LongRedBlackTree rbt, long key, Object value) {

        Object obj = rbt.get(key);
        if (!value.equals(obj)) {
            Assert.fail("Expected value for key "+key +" was "+value +
                    " but got "+obj+" instead");
        }
    }

}


