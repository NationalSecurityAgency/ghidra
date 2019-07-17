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

public class ShortIndexManagerTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public ShortIndexManagerTest() {
		super();
	}
	
    /**
     * regression test driver
     */
@Test
    public void testShortIndexManager() {
        ShortIndexManager imgr = new ShortIndexManager();

        System.out.println("test basic allocation");

        short index;
        for(short i=0;i<10;i++) {
            if ((index = imgr.allocate()) != i) {
                Assert.fail("Allocate: expected "+i+", and got "+index);
            }
        }


        System.out.println("test deallocation");
        for(short i=5;i<8;i++) {
            imgr.deallocate(i);
        }
        for(short i = 7;i>=5;i--) {
            if ((index = imgr.allocate()) != i) {
                Assert.fail("Deallocate: expected "+i+", and got "+index);
            }
        }
        if (imgr.allocate() != 10) {
            Assert.fail("Deallocate: unexpected allocated index for 10");
        }


        System.out.println("test clear all");
        imgr.clear();
        for(int i=0;i<10;i++) {
            if ((index = imgr.allocate()) != i) {
                Assert.fail("ClearAll: expected "+i+", and got "+index);
            }
        }

   }//end doTest()

}

