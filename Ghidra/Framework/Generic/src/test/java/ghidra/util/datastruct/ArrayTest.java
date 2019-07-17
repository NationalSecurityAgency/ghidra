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
/*
 * ByteArrayTest.java
 *
 * Created on February 11, 2002, 4:04 PM
 */

package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 *
 * @version 
 */
public class ArrayTest extends AbstractGenericTest {

    /** Creates new ByteArrayTest */
    public ArrayTest() {
        super();
    }
    
@Test
    public void testByteArray() {
        ByteArray ba = new ByteArray();
        ba.put(2,(byte)2);
        ba.put(8,(byte)8);
        ba.put(17,(byte)17);
        assertEquals(2,ba.get(2));
        assertEquals(8,ba.get(8));
        assertEquals(17,ba.get(17));
        assertEquals(0,ba.get(0));
        assertEquals(0,ba.get(0));
        assertEquals(0,ba.get(1000));
        ba.remove(8);
        ba.remove(17);
        assertEquals(0,ba.get(8));
        assertEquals(0,ba.get(17));
        assertEquals(2,ba.lastNonZeroIndex);
        assertEquals(4,ba.bytes.length);
    }
@Test
    public void testShortArray() {
        ShortArray sa = new ShortArray();
        sa.put(2,(short)2);
        sa.put(8,(short)8);
        sa.put(17,(short)17);
        assertEquals(2,sa.get(2));
        assertEquals(8,sa.get(8));
        assertEquals(17,sa.get(17));
        assertEquals(0,sa.get(0));
        assertEquals(0,sa.get(0));
        assertEquals(0,sa.get(1000));
    }
   
@Test
    public void testIntArray() {
        IntArray ia = new IntArray();
        ia.put(2,2);
        ia.put(8,8);
        ia.put(17,17);
        assertEquals(2,ia.get(2));
        assertEquals(8,ia.get(8));
        assertEquals(17,ia.get(17));
        assertEquals(0,ia.get(0));
        assertEquals(0,ia.get(0));
        assertEquals(0,ia.get(1000));
    }
@Test
    public void testLongArray() {
        LongArray la = new LongArray();
        la.put(2,2);
        la.put(8,8);
        la.put(17,17);
        assertEquals(2l,la.get(2));
        assertEquals(8l,la.get(8));
        assertEquals(17l,la.get(17));
        assertEquals(0l,la.get(0));
        assertEquals(0l,la.get(0));
        assertEquals(0l,la.get(1000));
    }
@Test
    public void testBooleanArray() {
        BooleanArray ba = new BooleanArray();
        for(int i=0;i<100;i++) {
            test(ba, i);
        }

    }
    private void test(BooleanArray ba, int n) {
        assertEquals("n = "+n,false, ba.get(n));
        ba.put(n,true);
        for(int i=0;i<n;i++) {
            assertEquals("n = "+n+"i = "+i,false, ba.get(i));
        }
        assertEquals("n = "+n,true,ba.get(n));
        for(int i=n+1;i<n+10;i++) {
            assertEquals("n = "+n+"i = "+i,false, ba.get(i));
        }
        ba.put(n,false);
        for(int i=0;i<n+10;i++) {
            assertEquals("n = "+n+"i = "+i,false, ba.get(i));
        }
    
    }
           
}
