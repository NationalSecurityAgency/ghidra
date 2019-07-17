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

import org.junit.*;

import generic.test.AbstractGenericTest;

/**
 * The order in which the methods are defined in this class
 * determine the order in which they are exercised by JUnit.
 * This order does not changed until JUnit is restarted. That is,
 * simply re-running JUnit will change the execution order.
 */
public class StackTest extends AbstractGenericTest {

	private Stack<String> stack1;
	private Stack<String> stack2;
	private Stack<String> stack3;
	private Stack<String> stack4;

	public StackTest() {
		super();
	}

	@Before
	public void setUp() {
		stack1 = new Stack<String>(25);
		stack2 = new Stack<String>();
		stack2.push("1");
		stack2.push("2");
		stack3 = new Stack<String>();
		stack3.push("A");
		stack4 = new Stack<String>();
		stack4.push("1");
		stack4.push("2");
	}

	@After
	public void tearDown() {
		stack1 = null;
		stack2 = null;
		stack3 = null;
		stack4 = null;
	}

	@Test
    public void testSearch() {
		assertEquals(0, stack4.search("1"));
		assertEquals(1, stack4.search("2"));
		assertEquals(-1, stack4.search("3"));
	}

	@Test
    public void testPop() {
		assertEquals("A", stack3.pop());
		assertEquals(false, stack2.pop().equals("A"));
		assertEquals(true, stack2.push("3").equals("3"));
		assertEquals("3", stack2.pop());
	}

	@Test
    public void testPush() {
		assertEquals("3", stack2.push("3"));
		assertEquals("3", stack2.pop());
	}

	@Test
    public void testEquals() {
		assertEquals(stack1, stack1);
		assertEquals(false, stack1.equals(stack2));
		assertEquals(true, stack2.equals(stack4));
	}

	@Test
    public void testEmpty() {
		assertEquals(true, stack1.isEmpty());
		assertEquals(false, stack2.isEmpty());
		assertEquals(false, stack3.isEmpty());
	}

	@Test
    public void testPeek() {
		assertEquals("2", stack2.peek());
		assertEquals("A", stack3.peek());
	}
}
