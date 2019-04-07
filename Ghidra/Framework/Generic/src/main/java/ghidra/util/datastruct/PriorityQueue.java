/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.util.LinkedList;
import java.util.TreeMap;

/**
 * Maintains a list of objects in priority order where priority is just 
 * an integer value.  The object with the lowest
 * priority number can be retrieved using getFirst() and the object with the highest
 * priority number can be retrieved using getLast().
 * 
 */
public class PriorityQueue<T> {
	private int size = 0;
	private TreeMap<Integer, LinkedList<T>> tree = new TreeMap<Integer, LinkedList<T>>();
	
	/**
	 * Adds the given object to the queue at the appropriate insertion point based
	 * on the given priority.
	 * @param obj the object to be added.
	 * @param priority the priority assigned to the object.
	 */
	public void add(T obj, int priority) {
		Integer key = new Integer(priority);
		LinkedList<T> list = tree.get(key);
		if (list == null) {
			list = new LinkedList<T>();
			tree.put(key, list);
		}
		list.addLast(obj);
		size++;	
	}
	
	/**
	 * Returns the number of objects in the queue.
	 */
	public int size() {
		return size;
	}
	
	/**
	 * Returns true if the queue is empty.
	 */
	public boolean isEmpty() {
		return size == 0;
	}

	/**
	 * Returns the object with the lowest priority number in the queue.
	 * If more than one object has the same priority, then the object that
	 * was added to the queue first is considered to have the lower priority value.
	 * Null is returned if the queue is empty.
	 */
	public T getFirst() {
		if (tree.isEmpty()) {
			return null;
		}
		Integer key = tree.firstKey();
		LinkedList<T> list = tree.get(key);
		return list.getFirst();
	}
	
	/**
	 * Returns the priority of the object with the lowest priority in the queue.
	 * Null returned if the queue is empty.
	 */
	public Integer getFirstPriority() {
		if (tree.isEmpty()) {
			return null;
		}
		Integer key = tree.firstKey();
		return key;
	}
		
	/**
	 * Returns the object with the highest priority number in the queue.
	 * If more than one object has the same priority, then the object that
	 * was added to the queue last is considered to have the higher priority value.
	 * Null is returned if the queue is empty.
	 */
	public T getLast() {
		if (tree.isEmpty()) {
			return null;
		}
		Integer key = tree.lastKey();
		LinkedList<T> list = tree.get(key);
		return list.getLast();
	}
	
	/**
	 * Returns the priority of the object with the highest priority in the queue.
	 * Null returned if the queue is empty.
	 */
	public Integer getLastPriority() {
		if (tree.isEmpty()) {
			return null;
		}
		Integer key = tree.lastKey();
		return key;
	}

	/**
	 * Removes and returns the object with the lowest priority number in the queue.
	 * If more than one object has the same priority, then the object that
	 * was added to the queue first is considered to have the lower priority value.
	 * Null is returned if the queue is empty.
	 * @return the object with the lowest priority number or null if the list is empty.
	 */
	public T removeFirst() {
		if (tree.isEmpty()) {
			return null;
		}
		size--;
		Integer key = tree.firstKey();
		LinkedList<T> list = tree.get(key);
		if (list.size() == 1) {
			tree.remove(key);
		}
		return list.removeFirst();
	}
	
	/**
	 * Removes and returns the object with the highest priority number in the queue.
	 * If more than one object has the same priority, then the object that
	 * was added to the queue last is considered to have the higher priority value.
	 * Null is returned if the queue is empty.
	 * @return the object with the highest priority number or null if the list is empty.
	 */
	public T removeLast() {	
		if (tree.isEmpty()) {
			return null;
		}
		size--;
		Integer key = tree.lastKey();
		LinkedList<T> list = tree.get(key);
		if (list.size() == 1) {
			tree.remove(key);
		}
		return list.removeLast();
	}

	/**
	 * Removes all objects from the queue.
	 */
	public void clear() {
		size = 0;
		tree.clear();
	}
}
