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
 * DataTableTest.java
 *
 * Created on February 11, 2002, 4:18 PM
 */

package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;


/**
 *
 * @version 
 */
public class DataTableTest extends AbstractGenericTest {

    /** Creates new DataTableTest */
    public DataTableTest() {
        super();
    }
@Test
    public void testByteArrays() {
        DataTable dt = new DataTable();
        
        dt.putByte(5,0,(byte)5);
        dt.putByte(2,1,(byte)2);
        dt.putByte(7,3,(byte)7);
        
        assertEquals(5,dt.getByte(5,0));
        assertEquals(2,dt.getByte(2,1));
        assertEquals(7,dt.getByte(7,3));
        assertEquals(0,dt.getByte(0,1));
        assertEquals(0,dt.getByte(5,3));
        
        try {
            dt.getByte(5,2);
            Assert.fail();
        } catch(NullPointerException e) {
        }
        
        try {
            dt.getByte(0,4);
            Assert.fail();
        } catch(IndexOutOfBoundsException e) {
        }
        
        try {
            dt.getByte(20,0);
        } catch(IndexOutOfBoundsException e) {
            Assert.fail();
        }

    }

}
