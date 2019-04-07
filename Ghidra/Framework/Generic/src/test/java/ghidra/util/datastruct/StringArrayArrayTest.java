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
public class StringArrayArrayTest extends AbstractGenericTest {

    /** Creates new ArrayArrayTest */
    public StringArrayArrayTest() {
        super();
    }
@Test
    public void testSimpleGetPut() {
        StringArrayArray saa = new StringArrayArray();
        assertNull(saa.get(0));
        assertNull(saa.get(100));
        saa.put(0,new String[] {"0","1",null,"2"});
        String[] s = saa.get(0);
        assertEquals(4,s.length);
        assertEquals("0",s[0]);
        assertEquals("1",s[1]);
        assertNull(s[2]);
        assertEquals("2",s[3]);
        
        saa.put(1,new String[]{});
        s = saa.get(1);
        assertEquals(0,s.length);
        saa.put(2,new String[]{"5"});
        s = saa.get(2);
        assertEquals(1,s.length);
        
        saa.remove(1);
        assertNull(saa.get(1));
        
        saa.put(10, new String[] {"0","1","2","3","4","5","6"});
        s = saa.get(10);
        assertEquals(7,s.length);
        assertEquals("0",s[0]);
        assertEquals("6",s[6]);
    }
@Test
    public void testMany() {
        StringArrayArray saa = new StringArrayArray();

        for(int i=0;i<1000;i++) {
            saa.put(i,new String[]{""+i,"1","2","3"});
        }
        for(int i=0;i<1000;i++) {
            String[] s = saa.get(i);
            assertEquals(4, s.length);
            assertEquals(""+i, s[0]);
            assertEquals("1", s[1]);
        }
        
        for(int i=999;i>=0;i--) {
            saa.remove(i);
        }
 
    }

}
