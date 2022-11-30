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

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.*;

/**
 * Class for storing a weak reference to object instances. Objects of type T can be placed in this 
 * store and they will remain there until there are no references to that object. Note 
 * that this is not a Set and you can have multiple instances that are "equal" in this store.The 
 * main purpose of this store is to be able to get all objects in the store that are still 
 * referenced.  This is useful when you need to visit all in use items.   
 * <p>
 * This class is thread safe.
 *
 * @param <T> The type of objects stored in this WeakStore
 */
public class WeakStore<T> {
	protected ReferenceQueue<T> refQueue;
	private Link<T> first;
	private Link<T> last;
	private int size = 0;

	public WeakStore() {
		refQueue = new ReferenceQueue<>();
	}

	/**
	 * Returns the number of objects of type T remaining in the store. Those that are remaining
	 * are either still referenced
	 * @return the number of objects still in the store that haven't yet been garbage collected
	 */
	public synchronized int size() {
		processQueue();
		return size;
	}

	/** 
	 * returns a list of all the objects in this store
	 * @return a list of all the objects in this store
	 */
	public synchronized List<T> getValues() {
		processQueue();
		List<T> values = new ArrayList<>();
		for (Link<T> l = first; l != null; l = l.nextLink) {
			T value = l.get();
			if (value != null) {
				values.add(value);
			}
		}
		return values;
	}

	/**
	 * Adds the given value to the store
	 * @param value the instance being added to the store
	 */
	public synchronized void add(T value) {
		Objects.requireNonNull(value);

		processQueue();
		Link<T> newLink = new Link<>(last, value, null, refQueue);
		if (last == null) {
			first = newLink;
		}
		else {
			last.nextLink = newLink;
		}
		last = newLink;
		size++;
	}

	@SuppressWarnings("unchecked")
	private void processQueue() {
		Link<T> ref;
		while ((ref = (Link<T>) refQueue.poll()) != null) {
			remove(ref);
		}
	}

	private void remove(Link<T> link) {
		if (link.previousLink == null) {
			first = link.nextLink;
		}
		else {
			link.previousLink.nextLink = link.nextLink;
		}
		if (link.nextLink == null) {
			last = link.previousLink;
		}
		else {
			link.nextLink.previousLink = link.previousLink;
		}
		size--;
	}

	private static class Link<T> extends WeakReference<T> {
		private Link<T> nextLink;
		private Link<T> previousLink;

		public Link(Link<T> previous, T value, Link<T> next, ReferenceQueue<T> refQueue) {
			super(value, refQueue);
			this.nextLink = next;
			this.previousLink = previous;
		}
	}
}
