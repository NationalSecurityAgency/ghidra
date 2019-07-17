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
package generic.util;

import java.util.Deque;

/**
 * A context utility allowing stack management via a try-with-resources block
 * @param <E> the type of element pushed to the stack
 */
public class DequePush<E> implements AutoCloseable {
	protected Deque<E> stack;

	protected DequePush(Deque<E> stack, E elem) {
		this.stack = stack;
		stack.push(elem);
	}

	@Override
	public void close() {
		stack.pop();
	}

	/**
	 * Push an element to the given stack
	 * @param stack the stack
	 * @param elem the element
	 * @return a context used to pop the element
	 * 
	 * This is an idiomatic convenience, as in a try-with-resources block:
	 * <pre>
	 * {@code
	 * Deque<String> stack = new LinkedList<>();
	 * try(DequePush<?> p = DequePush.push(stack, "Hello, World!\n")) {
	 *     System.out.println(stack.peek());
	 * }
	 * }
	 * </pre>
	 * 
	 * This idiom can be very useful if there is complex logic between the push and pop. It's easy
	 * to forget to pop; however, this convenience comes at the cost of a heap allocation.
	 */
	public static <E> DequePush<E> push(Deque<E> stack, E elem) {
		return new DequePush<>(stack, elem);
	}
}
