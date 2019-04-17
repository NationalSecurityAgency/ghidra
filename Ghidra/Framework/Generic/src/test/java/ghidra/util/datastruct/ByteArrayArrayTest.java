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
 * ArrayArrayTest.java
 *
 * Created on February 13, 2002, 3:33 PM
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
public class ByteArrayArrayTest extends AbstractGenericTest {

    /** Creates new ArrayArrayTest */
    public ByteArrayArrayTest() {
        super();
    }
@Test
    public void testSimpleGetPut() {
        ByteArrayArray baa = new ByteArrayArray();
        assertNull(baa.get(0));
        assertNull(baa.get(100));
        baa.put(0,new byte[] {0,1,2});
        byte[] b = baa.get(0);
        assertEquals(3,b.length);
        assertEquals(0,b[0]);
        assertEquals(1,b[1]);
        assertEquals(2,b[2]);
        
        baa.put(1,new byte[]{});
        b = baa.get(1);
        assertEquals(0,b.length);
        baa.put(2,new byte[]{5});
        b = baa.get(2);
        assertEquals(1,b.length);
        
        baa.remove(1);
        assertNull(baa.get(1));
    }
@Test
    public void testMany() {
        ByteArrayArray baa = new ByteArrayArray();

        for(int i=0;i<1000;i++) {
            byte t = (byte)i;
            baa.put(i,new byte[]{t,(byte)(t+1),(byte)(t+2),(byte)(t+3),(byte)(t+4)});
        }
        for(int i=0;i<1000;i++) {
            byte[] b = baa.get(i);
            assertEquals(5, b.length);
            for(int j=0;j<5;j++) {
                byte t = (byte)(i+j);
                assertEquals("i="+i+"j="+j,t,b[j]);
            }
        }
        
        for(int i=999;i>=0;i--) {
            baa.remove(i);
        }
        assertEquals(4,baa.starts.length);
        assertEquals(10,baa.bytes.length);
        for(int i=0;i<1000;i++) {
            byte t = (byte)i;
            baa.put(i,new byte[]{t,(byte)(t+1),(byte)(t+2),(byte)(t+3),(byte)(t+4)});
        }
        for(int i=0;i<1000;i++) {
            byte[] b = baa.get(i);
            assertEquals(5, b.length);
            for(int j=0;j<5;j++) {
                byte t = (byte)(i+j);
                assertEquals("i="+i+"j="+j,t,b[j]);
            }
        }
 
    }

}
