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

public class RedBlackKeySetTest extends AbstractGenericTest {

    /**
	 * Constructor
	 * @param arg0
	 */
	public RedBlackKeySetTest() {
		super();
	}
	
    /**
     * regression test driver
     */
@Test
    public void testRedBlackKeySet() {
        System.out.println("Testing put method");
        RedBlackKeySet bt = new RedBlackKeySet((short)1000);
        bt.put((short)25);
        bt.put((short)234);
        bt.put((short)2);
        bt.put((short)999);
        bt.put((short)0);
        bt.put((short)700);

        System.out.println("Testing first/next methods");
        expect(bt, new int[]{0,2,25,234,700,999});

        System.out.println("Testing last/previous methods");
        expectBackwards(bt, new int[]{999,700,234,25,2,0});

        System.out.println("Testing getNextMethod");
        if (bt.getNext((short)500) != 700) {
            Assert.fail("Expected next value after 500 to be 700, but instead got"+bt.getNext((short)500));
        }

        System.out.println("Testing delete");
        bt.remove((short)234);
        bt.remove((short)2);
        bt.remove((short)999);
        expect(bt, new int[] {0,25,700});
        System.out.println("Testing remove all");
        bt.removeAll();
        expect(bt, new int[]{});


        System.out.println("Test putting all keys in set");
        for(int i=0;i<1000;i++) {
            bt.put((short)i);
        }

        short n = bt.getFirst();
        for(int i=0;i<1000;i++) {
            if (n != i) {
                Assert.fail("All keys failed!  n = "+n+" and i = "+i);
            }
            n = bt.getNext(n);
        }
        if (n != -1) {
            Assert.fail("Too many keys in full RedBlackKeySet!");
        }


    }//end doTest()

    public static void expect(RedBlackKeySet bt, int[] values) {
        short k = bt.getFirst();
        for(int i=0;i<values.length;i++) {
            if (k != values[i]) {
                Assert.fail("Expected "+values[i]+ " and got "+k);
            }
            k = bt.getNext(k);
        }
        if (k != -1) {
            Assert.fail("More values in RedBlackKeySet than expeced");
        }
    }
    public static void expectBackwards(RedBlackKeySet bt, int[] values) {
        short k = bt.getLast();
        for(int i=0;i<values.length;i++) {
            if (k != values[i]) {
                Assert.fail("Expected "+values[i]+ " and got "+k);
            }
            k = bt.getPrevious(k);
        }
        if (k != -1) {
            Assert.fail("More values in RedBlackKeySet than expeced");
        }
    }

}
