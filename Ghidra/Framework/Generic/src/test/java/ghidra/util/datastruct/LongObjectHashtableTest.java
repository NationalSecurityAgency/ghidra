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

public class LongObjectHashtableTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public LongObjectHashtableTest() {
		super();
	}

@Test
    public void testLongObjectHashtable() {

		LongObjectHashtable<String> ht = new LongObjectHashtable<>();
        System.out.println("Test put method");

        ht.put(10000, "bill");
        ht.put(20000, "john");
        ht.put(30000, "fred");
        ht.put(40000, "tom");

        test(ht, 10000, "bill");
        test(ht, 20000, "john");
        test(ht, 30000, "fred");
        test(ht, 40000, "tom");
        test(ht, 50000, null);

        System.out.println("Test contains method");

        testContains(ht, new long[]{10000,20000,30000,40000}, "Add");

        System.out.println("Test size method");
        if (ht.size() != 4) {
            Assert.fail("size should be 4, but it is "+ht.size());
        }

        System.out.println("Test remove");
        ht.remove(20000);

        if (ht.size() != 3) {
            Assert.fail("size should be 3, but it is "+ht.size());
        }
        testContains(ht, new long[]{10000,30000,40000}, "Remove");

        System.out.println("Test removeAll");
        ht.removeAll();
        if (ht.size() != 0) {
            Assert.fail("size should be 0, but it is "+ht.size());
        }
        testContains(ht,new long[]{}, "RemoveAll");


        System.out.println("Test grow by adding 500 values");
        for(int i=0;i<500;i++) {
            ht.put(i*100, "LAB"+i);
        }

        for(int i= 0;i<50000;i++) {
            if (ht.contains(i)) {
                if (i%100 != 0) {
                    Assert.fail("hashtable contains key "+i+", but it shouldn't");
                }
            }
            else {
                if (i%100 == 0) {
                    Assert.fail("hashtable should contain key "+i+", but it doesn't");
                }
            }
        }
    }

	public static void test(LongObjectHashtable<String> ht, long key, Object value) {

        if (value == null) {
            if (ht.get(key) != null) {
                Assert.fail("Value at key "+key+" should be null! "+
                        "Instead it contains "+ht.get(key));
            }
        }
        else {
            if (!ht.get(key).equals(value)) {
                Assert.fail("Value at key "+key+" should be "+value+
                        " but instead is "+ht.get(key));
            }
        }
    }

	public static void testContains(LongObjectHashtable<String> ht, long[] keys, String test) {

        for(int i=0;i<keys.length;i++) {
            if (!ht.contains(keys[i])) {
                Assert.fail("hastable should contain key "+keys[i]+", but it doesn't");
            }
        }

        for(int i= 0;i<=50000;i++) {
            if (ht.contains(i)) {
                if (!contains(keys,i)) {
                    Assert.fail("hashtable contains key "+i+", but it shouldn't");
                }
            }
        }
    }

    public static boolean contains(long[] keys, long key) {
        for (long key2 : keys) {
            if (key2 == key) {
                return true;
            }
        }
        return false;
    }

}


