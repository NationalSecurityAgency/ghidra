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
package ghidra.util.prop;

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.LongIterator;

// Test the LongIteratorImpl and LongIteratorMatcherImpl classes.

public class IteratorTest extends AbstractGenericTest {


	public IteratorTest() {
		super();
	}

@Test
    public void testAll() {

        StringPropertySet pm = new StringPropertySet("Test");
        for (int i=0; i<20; i++) {
            String s = "test " + (i+10);
            pm.putString(i+10, s);
        }
        LongIterator it = pm.getPropertyIterator(10, 30);

		int i = 10;
        while (it.hasNext()) {
            long index = it.next();
			assertEquals(i, index);
            if (it.hasPrevious()) {
                index = it.previous();
				assertEquals(i,index);
                index = it.next();// so we don't go into an infinite loop
            }
			i++;
        }

        it = pm.getPropertyIterator(12);
		i=11;
        while (it.hasPrevious()) {
            long index = it.previous();
        	assertEquals(i,index); 
            if (it.hasNext()) {
                index = it.next();
                assertEquals(i, index);
                index = it.previous();// so we don't go into an infinite loop
            }
            i--;
        }

        it = pm.getPropertyIterator(5, 15);
		i = 10;
        while (it.hasNext()) {
            long index = it.next();
			assertEquals(i, index);
            if (it.hasPrevious()) {
                index = it.previous();
				assertEquals(i, index);
                index = it.next();// so we don't go into an infinite loop
            }
            i++;
        }

        pm.removeRange(0, 2000);
        it = pm.getPropertyIterator(5, 15);
        if (it.hasPrevious()) {
			Assert.fail();
        }


    }//end doTest()

}
