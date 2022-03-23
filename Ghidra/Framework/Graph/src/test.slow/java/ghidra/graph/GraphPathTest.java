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
package ghidra.graph;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class GraphPathTest {

    // GraphPath object used for (almost) all tests.
    GraphPath<Integer> GP;

    /**
     * Setup function to have a new GraphPath instance for every test that is filled with 21
     * vertices.
     */
    @Before
    public void setUp() {
        GP = new GraphPath<>();
        for (int i = 0 ; i <= 20; i++) {
            GP.add(i);
        }
    }

    /**
     * Test to verify if copy() function works correctly. Reinitializes the GraphPath object and
     * adds three vertices to it. GraphPath is then copied and with assertions the test checks if
     * all three vertices exist in the copy, and that they are the only vertices in the GraphPath.
     */
    @Test
    public void testCopy() {
        GP = new GraphPath<>();

        GP.add(1);
        GP.add(2);
        GP.add(3);

        GraphPath<Integer> graphPathCopy = GP.copy();

        Assert.assertTrue(graphPathCopy.contains(1));
        Assert.assertTrue(graphPathCopy.contains(2));
        Assert.assertTrue(graphPathCopy.contains(3));
        Assert.assertEquals(3, graphPathCopy.size());
    }

    /**
     * Test to verify if startsWith() function works correctly. A smaller GraphPath is given as an
     * argument in this test. Asserts check if the startsWith() function returns true, when the
     * GraphPath actually starts with the GraphPath passed in the parameter. Also check if false
     * is returned with a GraphPath that the GraphPath object does not start with.
     */
    @Test
    public void testStartsWith_SmallerGraphPath() {
        GraphPath<Integer> graphPathStart = new GraphPath<>();
        for (int i = 0; i < 5; i++) {
            graphPathStart.add(i);
        }

        Assert.assertTrue(GP.startsWith(graphPathStart));
        Assert.assertFalse(GP.startsWith(new GraphPath<>(6)));
    }

    /**
     * Test to verify if startsWith() function works correctly. A larger GraphPath is given as an
     * argument in this test. Asserts check if the startsWith() function returns false, when the
     * GraphPath in the argument is larger than the GraphPath object.
     */
    @Test
    public void testStartsWith_LargerGraphPath() {
        GraphPath<Integer> largerGraphPath = new GraphPath<>();
        for (int i = 0; i < 25; i++) {
            largerGraphPath.add(i);
        }

        Assert.assertFalse(GP.startsWith(largerGraphPath));
    }

    /**
     * Test to verify if getCommonStartPath() function works correctly. A different GraphPath to GP
     * is created and later on with asserts, the test checks if the commonStartPath contains the
     * correct elements and has the right length.
     */
    @Test
    public void testGetCommonStartPath() {
        GraphPath<Integer> commonStartGraphPath = new GraphPath<>();
        for (int i = 0; i < 10; i++) {
            commonStartGraphPath.add(i);
        }

        GraphPath<Integer> differentGraphPath = commonStartGraphPath.copy();

        for (int i = 90; i < 100; i++) {
            differentGraphPath.add(i);
        }

        GraphPath<Integer> commonStartPathResult =
                commonStartGraphPath.getCommonStartPath(differentGraphPath);

        for (int i = 0; i < commonStartPathResult.size(); i++) {
            Assert.assertEquals(commonStartGraphPath.get(i), commonStartPathResult.get(i));
        }

        Assert.assertEquals(commonStartGraphPath.size(), commonStartPathResult.size());
    }

    /**
     * Test to verify if getCommonStartPath() function works correctly. A different GraphPath to GP
     * is created and later on with asserts, the test checks if the commonStartPath contains the
     * correct elements and has the right length.
     */
    @Test
    public void getCommonStartPath2() {
        GraphPath<Integer> commonStartGraphPath = new GraphPath<>();
        for (int i = 0; i < 10; i++) {
            commonStartGraphPath.add(i);
        }

        for (int i = 0; i < 10; i++) {
            commonStartGraphPath.add(i);
        }

        GraphPath commonStartPathResult = commonStartGraphPath.getCommonStartPath(GP);


        for (int i = 0; i < commonStartPathResult.size(); i++) {
            Assert.assertEquals(commonStartPathResult.get(i), GP.get(i));
        }

        Assert.assertEquals(10, commonStartPathResult.size());
    }

    /**
     * Test to verify if size() function works correctly. Reinitializes GP and adds three elements
     * to it. Assert checks if size of GraphPath is then three.
     */
    @Test
    public void size() {
        GP = new GraphPath<>();
        GP.add(1);
        GP.add(2);
        GP.add(3);

        Assert.assertEquals(3, GP.size());
    }

    /**
     * Test to verify if contains() function works correctly. A vertex with a random integer is
     * added to the GraphPath. Assertion checks if vertex is really added to the GraphPath. This is
     * done twice.
     */
    @Test
    public void contains() {
        Random r = new Random();
        int randomInt = r.nextInt(100000);
        GP.add(randomInt);

        Assert.assertTrue(GP.contains(randomInt));

        randomInt = r.nextInt(100000);
        GP.add(randomInt);

        Assert.assertTrue(GP.contains(randomInt));

    }

    /**
     * Test to verify if getLast() function works correctly. At setUp() a GraphPath is created
     * containing 21 vertices, with the last vertex having integer 20. Assert checks if getLast()
     * function returns 20, since it is the last vertex in the GraphPath.
     */
    @Test
    public void getLast() {
        Assert.assertEquals(20, (int) GP.getLast());
    }

    /**
     * Test to verify if depth() function works correctly. At setUp() a GraphPath is created
     * containing 21 vertices, with the last vertex having integer 20. A random vertex is selected
     * from the GraphPath. Since in the test cases the depth is equal to the vertex its integer,
     * an assertEquals with the two is performed.
     */
    @Test
    public void depth() {
        Random r = new Random();
        int randomInt = r.nextInt(GP.size());

        Assert.assertEquals(randomInt, GP.depth(randomInt));

    }

    /**
     * Test to verify if get() function works correctly. At setUp() a GraphPath is created
     * containing 21 vertices, with the last vertex having integer 20. A random vertex is selected
     * from the GraphPath. Since in the test cases the index is equal to the vertex its integer,
     * an assertEquals with the two is performed.
     */
    @Test
    public void get() {
        Random r = new Random();
        int randomInt = r.nextInt(GP.size());

        Assert.assertEquals(randomInt, (int) GP.get(randomInt));
    }

    /**
     * Test to verify if removeLast() function works correctly. At setUp() a GraphPath is created
     * containing 21 vertices, with the last vertex having integer 20. Assert checks if this is the
     * case. Second assert checks if 20 is again returned when removeLast() is called. Final assert
     * checks if now getLast() returns 19, to check if removeLast() actually worked.
     */
    @Test
    public void removeLast() {
        Assert.assertEquals(20, (int) GP.getLast());
        Assert.assertEquals(20, (int) GP.removeLast());
        Assert.assertEquals(19, (int) GP.getLast());
    }

    /**
     * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
     * created containing 21 vertices, with the last vertex having integer 20. Testcase creates a
     * new HashSet with integers 0-10. Then assertEquals checks if HashSet returned by
     * getPredecessors() is the same as this HashSet.
     */
    @Test
    public void getPredecessors() {
        Set<Integer> predecessors = new HashSet<>();
        for (int i = 0; i <= 10; i++) {
            predecessors.add(i);
        }

        Set<Integer> predecessorsSet = GP.getPredecessors(10);
        Assert.assertEquals(predecessors, predecessorsSet);
    }

    /**
     * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
     * created containing 21 vertices, with the last vertex having integer 20. Assert checks if
     * getPredecessors() returns an empty HashSet whenever it is called with a larger index than
     * the amount of vertices contained in the GraphPath.
     */
    @Test
    public void getPredecessors_LargerIndex() {
        Set<Integer> predecessorsSet = GP.getPredecessors(21);
        Assert.assertEquals(0, predecessorsSet.size());
    }

    /**
     * Test to verify if getSuccessors() function works correctly. At setUp() a GraphPath is
     * created containing 21 vertices, with the last vertex having integer 20. Testcase creates a
     * new HashSet with integers 10-20. Then assertEquals checks if HashSet returned by
     * getSuccessors() is the same as this HashSet.
     */
    @Test
    public void getSuccessors() {
        Set<Integer> successors = new HashSet<>();
        for (int i = 10; i <= 20; i++) {
            successors.add(i);
        }

        Set<Integer> successorsSet = GP.getSuccessors(10);
        Assert.assertEquals(successors, successorsSet);
    }

    /**
     * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
     * created containing 21 vertices, with the last vertex having integer 20. Assert checks if
     * getSuccessors() returns an empty HashSet whenever it is called with a larger index than
     * the amount of vertices contained in the GraphPath.
     */
    @Test
    public void getSuccessors_LargerIndex() {
        Set<Integer> successorsSet = GP.getSuccessors(GP.size());
        Assert.assertEquals(0, successorsSet.size());
    }
}
