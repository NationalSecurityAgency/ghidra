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

import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * <p>
 * The Stack class represents a last-in-first-out (LIFO) stack of objects.
 * It extends class ArrayList with five operations that allow an array list
 * to be treated as a stack. The usual push and pop operations are provided,
 * as well as a method to peek at the top item on the stack, a
 * method to test for whether the stack is empty, and a method to search
 * the stack for an item and discover how far it is from the top.
 * </p>
 * <p>
 * When a stack is first created, it contains no items.
 * </p>
 * <p>
 * <b>Note: This implementation is not synchronized!</b>
 * </p>
 */
public class Stack<E> implements Iterable<E> {
	protected List<E> list;

	/**
	 * Creates an empty Stack.
	 */
	public Stack() {
		list = new ArrayList<E>();
	}

	/**
	 * Creates an empty Stack with specified capacity.
	 * @param initialCapacity the initial capacity.
	 */
	public Stack(int initialCapacity) {
		list = new ArrayList<E>(initialCapacity);
	}

	/**
	 * Copy Constructor.
	 * Creates a new stack using the items of the given stack.
	 * Only a shallow copy is performed.
	 * @param stack the stack to copy
	 */
	public Stack(Stack<E> stack) {
		list = new ArrayList<E>(stack.list);
	}

	/**
	 * Tests if this stack is empty.
	 */
	public boolean isEmpty() {
		return (list.size() == 0);
	}

	/**
	 * Looks at the object at the top of this stack without removing it from the stack.
	 */
	public E peek() {
		return (list.size() > 0 ? list.get(list.size() - 1) : null);
	}

	/**
	 * Removes the object at the top of this stack and returns that object as the value of this function.
	 */
	public E pop() {
		return (list.size() > 0 ? list.remove(list.size() - 1) : null);
	}

	/**
	 * Pushes an item onto the top of this stack.
	 * @param item the object to push onto the stack.
	 */
	public E push(E item) {
		if (list.add(item)) {
			return item;
		}
		return null;
	}

	/**
	 * Returns the position where an object is on this stack.
	 * @param o the object to search for.
	 */
	public int search(E o) {
		return list.indexOf(o);
	}

	/**
	 * Returns the number of elements in this stack.
	 * @return the number of elements in this stack
	 */
	public int size() {
		return list.size();
	}

	/**
	 * Returns the element at the specified depth in this stack.
	 * 0 indicates the bottom of the stack.
	 * size()-1 indicates the top of the stack. 
	 * @param depth the depth in the stack.
	 * @return the element at the specified depth in this stack
	 */
	public E get(int depth) {
		return list.get(depth);
	}

	/**
	 * Appends the given item to the top of the stack.
	 * @param item the new top of the stack
	 */
	public void add(E item) {
		list.add(item);
	}

	/**
	 * Clears the stack. All items will be removed.
	 */
	public void clear() {
		list.clear();
	}

	/**
	 * Returns an iterator over the items of the stack.
	 * The iterator starts from the bottom of the stack.
	 * @return an iterator over the items of the stack
	 */
	@Override
	public Iterator<E> iterator() {
		return list.iterator();
	}

	/**
	 * Returns a stream over this collection.
	 * 
	 * @return a stream over this collection.
	 */
	public Stream<E> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	@Override
	public int hashCode() {
		return list.hashCode();
	}

	// cannot check against Stack<E>, type info is erased at runtime
	@SuppressWarnings("rawtypes")
	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof Stack)) {
			return false;
		}

		Stack stack = (Stack) obj;
		return list.equals(stack.list);
	}

	@Override
	public String toString() {
		return list.toString();
	}
}
