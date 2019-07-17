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
 * StringArrayTest.java
 *
 * Created on February 14, 2002, 10:43 AM
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
public class StringArrayTest extends AbstractGenericTest {

    /** Creates new ArrayArrayTest */
    public StringArrayTest() {
        super();
    }
@Test
    public void testSimpleGetPut() {
        StringArray baa = new StringArray();
        assertNull(baa.get(0));
        assertNull(baa.get(100));
        baa.put(0,"hello");
        assertEquals("hello",baa.get(0));
        
        baa.put(1,"");
        String s = baa.get(1);
        assertEquals(0,s.length());
        baa.put(2,"a");
        assertEquals("a",baa.get(2));
        
        baa.remove(1);
        assertNull(baa.get(1));

        baa.remove(0);
        assertNull(baa.get(0));
    }
@Test
    public void testMany() {
        StringArray baa = new StringArray();

        for(int i=0;i<100000;i++) {
            String s = "this is line "+i;
            baa.put(i,s);
        }
        for(int i=0;i<100000;i++) {
            assertEquals("this is line "+i,baa.get(i));
        }
        
        for(int i=99999;i>=0;i--) {
            baa.remove(i);
        }
        assertEquals(4,baa.starts.length);
        assertEquals(10,baa.bytes.length);
    }

}
