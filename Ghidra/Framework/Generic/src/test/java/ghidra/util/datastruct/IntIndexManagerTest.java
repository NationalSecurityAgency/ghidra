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
import static org.junit.Assert.assertEquals;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class IntIndexManagerTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public IntIndexManagerTest() {
		super();
	}
	
    /**
     * regression test driver
     */
@Test
    public  void testIntIndexManager() {
        IntIndexManager imgr = new IntIndexManager();

        System.out.println("test basic allocation");

        for(int i=0;i<10;i++) {
        	assertEquals(i, imgr.allocate());
        }


        System.out.println("test deallocation");
        for(int i=5;i<8;i++) {
            imgr.deallocate(i);
        }
        for(int i = 7;i>=5;i--) {
        	assertEquals(i, imgr.allocate());
        }
        assertEquals(10, imgr.allocate());


        System.out.println("test clear all");
        imgr.clear();
        for(int i=0;i<10;i++) {
        	assertEquals(i, imgr.allocate());
        }

   }//end doTest()

}

