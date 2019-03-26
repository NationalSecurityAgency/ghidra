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

public class ShortByteHashtableTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public ShortByteHashtableTest() {
		super();
	}

@Test
    public void testShortByteHashtable() {

        ShortByteHashtable ht = new ShortByteHashtable();
        System.out.println("Test put method");

        ht.put((short)100, (byte)10);
        ht.put((short)200, (byte)20);
        ht.put((short)300, (byte)30);
        ht.put((short)400, (byte)40);

        test(ht, (short)100, (byte)10);
        test(ht, (short)200, (byte)20);
        test(ht, (short)300, (byte)30);
        test(ht, (short)400, (byte)40);

        try {
            byte value = ht.get((short)500);
            Assert.fail("The value "+value+" was found at key "+
                    "50000, but there should not have been a value there.");
        }
        catch(NoValueException ex) {
        }

        System.out.println("Test contains method");

        testContains(ht, new short[]{100,200,300,400}, "Add");

        System.out.println("Test size method");
        if (ht.size() != 4) {
            Assert.fail("size should be 4, but it is "+ht.size());
        }

        System.out.println("Test remove");
        ht.remove((short)200);

        if (ht.size() != 3) {
            Assert.fail("size should be 3, but it is "+ht.size());
        }
        testContains(ht, new short[]{100,300,400}, "Remove");

        System.out.println("Test removeAll");
        ht.removeAll();
        if (ht.size() != 0) {
            Assert.fail("size should be 0, but it is "+ht.size());
        }
        testContains(ht,new short[]{}, "RemoveAll");


        System.out.println("Test grow by adding 500 values");
        for(int i=0;i<5000;i++) {
            ht.put((short)(i*10), (byte)i);
        }

        for(int i= 0;i<5000;i++) {
            if (ht.contains((short)i)) {
                if (i%10 != 0) {
                    Assert.fail("hashtable contains key "+i+", but it shouldn't");
                }
            }
            else {
                if (i%10 == 0) {
                    Assert.fail("hashtable should contain key "+i+", but it doesn't");
                }
            }
        }
    }

    public static void test(ShortByteHashtable ht, short key, byte value) {

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

    public static void testContains(ShortByteHashtable ht, short[] keys, String test) {

        for(int i=0;i<keys.length;i++) {
            if (!ht.contains(keys[i])) {
                Assert.fail("hastable should contain key "+keys[i]+", but it doesn't");
            }
        }

        for(int i= 0;i<=50000;i++) {
            if (ht.contains((short)i)) {
                if (!contains(keys,(short)i)) {
                    Assert.fail("hashtable contains key "+i+", but it shouldn't");
                }
            }
        }
    }

    public static boolean contains(short[] keys, short key) {
        for(int i=0;i<keys.length;i++) {
            if (keys[i] == key) {
                return true;
            }
        }
        return false;
    }

}


