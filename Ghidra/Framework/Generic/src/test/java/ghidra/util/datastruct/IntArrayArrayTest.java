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
 * IntArrayArrayTest.java
 *
 * Created on February 14, 2002, 3:33 PM
 */

package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 *
 * 
 * @version 
 */
public class IntArrayArrayTest extends AbstractGenericTest {

    /** Creates new ArrayArrayTest */
    public IntArrayArrayTest() {
        super();
    }
@Test
    public void testSimpleGetPut() {
        IntArrayArray baa = new IntArrayArray();
        assertNull(baa.get(0));
        assertNull(baa.get(100));
        baa.put(0,new int[] {0,1,2});
        int[] b = baa.get(0);
        assertEquals(3,b.length);
        assertEquals(0,b[0]);
        assertEquals(1,b[1]);
        assertEquals(2,b[2]);
        
        baa.put(1,new int[]{});
        b = baa.get(1);
        assertEquals(0,b.length);
        baa.put(2,new int[]{5});
        b = baa.get(2);
        assertEquals(1,b.length);
        
        baa.remove(1);
        assertNull(baa.get(1));
    }
@Test
    public void testMany() {
        IntArrayArray baa = new IntArrayArray();

        for(int i=0;i<1000;i++) {
            int t = i;
            baa.put(i,new int[]{t,(t+1),(t+2),(t+3),(t+4)});
        }
        for(int i=0;i<1000;i++) {
            int[] b = baa.get(i);
            assertEquals(5, b.length);
            for(int j=0;j<5;j++) {
                int t = (i+j);
                assertEquals("i="+i+"j="+j,t,b[j]);
            }
        }
        
        for(int i=999;i>=0;i--) {
            baa.remove(i);
        }
        assertEquals(4,baa.starts.length);
        assertEquals(10,baa.ints.length);
        for(int i=0;i<1000;i++) {
            int t = i;
            baa.put(i,new int[]{t,(t+1),(t+2),(t+3),(t+4)});
        }
        for(int i=0;i<1000;i++) {
            int[] b = baa.get(i);
            assertEquals(5, b.length);
            for(int j=0;j<5;j++) {
                int t = (i+j);
                assertEquals("i="+i+"j="+j,t,b[j]);
            }
        }
 
    }

}
