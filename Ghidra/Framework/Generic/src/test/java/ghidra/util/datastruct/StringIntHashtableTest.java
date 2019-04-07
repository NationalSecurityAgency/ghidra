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
import ghidra.util.exception.NoValueException;

public class StringIntHashtableTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public StringIntHashtableTest() {
		super();
	}

@Test
    public void testStringIntHashtable() {

        StringIntHashtable ht = new StringIntHashtable();
        System.out.println("Test put method");

        ht.put("A", 100);
        ht.put("B", 200);
        ht.put("C", 300);
        ht.put("D", 400);

        test(ht, "A", 100);
        test(ht, "B", 200);
        test(ht, "C", 300);
        test(ht, "D", 400);

        try {
            int value = ht.get("G");
            Assert.fail("The value "+value+" was found at key "+
                    "G, but there should not have been a value there.");
        }
        catch(NoValueException ex) {
        }

        System.out.println("Test contains method");

        testContains(ht, new String[]{"A","B","C","D"}, "Add");

        System.out.println("Test size method");
        if (ht.size() != 4) {
            Assert.fail("size should be 4, but it is "+ht.size());
        }

        System.out.println("Test remove");
        ht.remove("B");

        if (ht.size() != 3) {
            Assert.fail("size should be 3, but it is "+ht.size());
        }
        testContains(ht, new String[]{"A","C","D"}, "Remove");

        System.out.println("Test removeAll");
        ht.removeAll();
        if (ht.size() != 0) {
            Assert.fail("size should be 0, but it is "+ht.size());
        }
        testContains(ht,new String[]{}, "RemoveAll");


        System.out.println("Test grow by adding 500 values");
        for(int i=0;i<500;i++) {
            ht.put("LAB"+(100*i), i);
        }

        for(int i= 0;i<50000;i++) {
            if (ht.contains("LAB"+i)) {
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

    public static void test(StringIntHashtable ht, String key, int value) {

        try {
            if (ht.get(key) != value) {
                Assert.fail("Value at key "+key+" should be "+value+
                            " but instead is "+ht.get(key));
            }
        }
        catch(NoValueException ex) {
            Assert.fail("No value found at key "+key+" but should have had value "+value);
        }
    }

    public static void testContains(StringIntHashtable ht, String[] keys, String test) {

        for(int i=0;i<keys.length;i++) {
            if (!ht.contains(keys[i])) {
                Assert.fail("hastable should contain key "+keys[i]+", but it doesn't");
            }
        }

        for(int i= 0;i<=50000;i++) {
            if (ht.contains("LAB"+i)) {
                if (!contains(keys,"LAB"+i)) {
                    Assert.fail("hashtable contains key "+i+", but it shouldn't");
                }
            }
        }
    }

    public static boolean contains(String[] keys, String key) {
        for(int i=0;i<keys.length;i++) {
            if (keys[i].equals(key)) {
                return true;
            }
        }
        return false;
    }

}


