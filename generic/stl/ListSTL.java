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
package generic.stl;

import java.util.Comparator;


public class ListSTL<T> {

	public static final String EOL = System.getProperty( "line.separator" );

	private ListNodeSTL<T> root = new ListNodeSTL<> ();
	private int size;

	@Override
	public String toString() {
		StringBuffer buffy = new StringBuffer( "ListSTL[size=" + size + "]\n" );
		int showSize = Math.min( 20, size() );
		ListNodeSTL<T> current = root.next;
		for ( int i = 0; i < showSize; i++ ) {
			buffy.append( "\t[" + i + "]=" + current.value ).append( EOL );
			current = current.next;
		}
		return buffy.toString();
	}

	// for debug
	public void printDebug() {
		StringBuffer buffy = new StringBuffer();
		IteratorSTL<T> begin = begin();
		while ( !begin.isEnd() ) {
			T t = begin.get();
			begin.increment();
			String value = t == null ? "null" : t.toString();
			buffy.append( value ).append( EOL );
		}
		System.err.println( buffy.toString() );
	}

	public IteratorSTL<T> begin() {
		return new ListIterator<>(this, root, root.next);
	}
	public IteratorSTL<T> end() {
		return new ListIterator<>(this, root, root);
	}
	public IteratorSTL<T> rBegin() {
		return new ReverseListIterator<>(this, root, root.prev);
	}
	public IteratorSTL<T> rEnd() {
		return new ReverseListIterator<>(this, root, root);
	}

	public int size() {
		return size;
	}

	public void clear() {
		size = 0;
		root = new ListNodeSTL<>();
	}
	public boolean isEmpty() {
		return size == 0;
	}
	public T front() {
		if (isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		return root.next.value;
	}
	public T back() {
		if (isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		return root.prev.value;
	}
	public void push_back(T value) {
		ListNodeSTL<T> newNode = new ListNodeSTL<>(root.prev, root, value);
		root.prev.next = newNode;
		root.prev = newNode;
		size++;
	}
	public void push_front(T value) {
		ListNodeSTL<T> newNode = new ListNodeSTL<>(root, root.next, value);
		root.next.prev = newNode;
		root.next = newNode;
		size++;
	}
	public IteratorSTL<T> insert(IteratorSTL<T> position, T value) {
		ListNodeSTL<T> newNode = new ListNodeSTL<>(root.prev, root, value);
		ListIterator<T> listIterator = (ListIterator<T>)position;

		newNode.next = listIterator.getNode();
		newNode.prev = listIterator.getNode().prev;
		newNode.prev.next = newNode;
		newNode.next.prev = newNode;
		size++;
//		if (size != computeSize()) {
//			throw new RuntimeException("Bad list state");
//		}
		return new ListIterator<>(this, root, newNode);
	}
//	private int computeSize() {
//		int computedSize = 0;
//		ListNodeSTL<T> node = root.next;
//		while(node != root) {
//			node = node.next;
//			computedSize++;
//		}
//		return computedSize;
//	}

	public void erase(IteratorSTL<T> position) {
		ListIterator<T> insertPos = (ListIterator<T>)position;
		if (this != insertPos.list) {
			throw new RuntimeException("Attempting to erase using an iterator from a different list");
		}
		ListNodeSTL<T> node = insertPos.getNode();

		node.prev.next = node.next;
		node.next.prev = node.prev;

		size--;
//		if (size != computeSize()) {
//			throw new RuntimeException("Bad list state");
//		}
	}


	public T pop_front() {
		if (isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		ListNodeSTL<T> node = root.next;

		node.next.prev = root;
		root.next = node.next;
		node.next = null;
		node.prev = null;
		size--;
		return node.value;

	}
	public T pop_back() {
		if (isEmpty()) {
			throw new IndexOutOfBoundsException();
		}
		ListNodeSTL<T> node = root.prev;
		node.prev.next = root;
		root.prev = node.prev;
		node.next = null;
		node.prev = null;
		size--;
		return node.value;

	}
	void adjustSize(int count) {
		size += count;
	}
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof ListSTL)) {
			return false;
		}
		ListSTL<?> other = (ListSTL<?>)obj;
		if (size != other.size) {
			return false;
		}
		IteratorSTL<?> thisIt = begin();
		IteratorSTL<?> otherIt = other.begin();
		while(!thisIt.isEnd()) {
			Object thisValue = thisIt.get();
			Object otherValue = otherIt.get();
			if (!thisValue.equals(otherValue)) {
				return false;
			}
			thisIt.increment();
			otherIt.increment();
		}
		return true;
	}

	public void sort(Comparator<T> comparator) {
		ListNodeSTL<T> TERMINAL = new ListNodeSTL<>();

		if (size <= 1) {
			return;
		}
		root.prev.next = TERMINAL;

		root.next = mergeSort(root.next, comparator, TERMINAL);
		ListNodeSTL<T> node = root.next;
		ListNodeSTL<T> prevNode = root;
		while(node != TERMINAL) {
			node.prev = prevNode;
			prevNode = node;
			node = node.next;
		}
		prevNode.next = root;
		root.prev = prevNode;
	}
	private static <T> ListNodeSTL<T> mergeSort(ListNodeSTL<T> c, Comparator<T> comparator, ListNodeSTL<T> TERMINAL) {
		ListNodeSTL<T> a;
		ListNodeSTL<T> b;

		if (c.next != TERMINAL) {
			a = c;
			b = c.next.next.next;
			while(b != TERMINAL) {
				c = c.next;
				b = b.next.next;
			}
			b = c.next;
			c.next = TERMINAL;
			a = mergeSort(a, comparator, TERMINAL);
			b = mergeSort(b, comparator, TERMINAL);
			return merge(a, b, comparator, TERMINAL);
		}
		return c;
	}
	/**
	 * moves a single element, decreasing the length of list by 1 and increasing this list by 1.
	 * @param position the position into this list where the element is to be inserted
	 * @param list the list from which the element is removed.
	 * @param listPosition the postion of the element to be removed.
	 */
	public void splice( IteratorSTL<T> position, ListSTL<T> list, IteratorSTL<T> listPosition ) {
		ListIterator<T> toPosition = (ListIterator<T>)position;
		ListIterator<T> fromPosition = (ListIterator<T>)listPosition;
		ListNodeSTL<T> node = fromPosition.getNode();
		ListNodeSTL<T> insertAtNode = toPosition.getNode();

		node.prev.next = node.next;
		node.next.prev = node.prev;
		list.size--;

		node.next = insertAtNode;
		node.prev = insertAtNode.prev;
		node.prev.next = node;
		node.next.prev = node;
		size++;
	}
	private static <T> ListNodeSTL<T> merge(ListNodeSTL<T> a, ListNodeSTL<T> b, Comparator<T> comparator, ListNodeSTL<T> TERMINAL) {
		ListNodeSTL<T> head = new ListNodeSTL<>();
		ListNodeSTL<T> c = head;
		do {
			if (b == TERMINAL || ((a != TERMINAL) && comparator.compare(a.value, b.value)<= 0)) {
				c.next = a;
				c = a;
				a = a.next;
			}
			else {
				c.next = b;
				c = b;
				b = b.next;
			}
		}
		while(c != TERMINAL);
		return head.next;
	}
//	public static void main(String[] args) {
//		ListSTL<Integer> list = new ListSTL<Integer>();
//		list.push_back(5);
//		list.push_back(10);
//		list.push_back(3);
//		list.push_back(7);
//		list.push_back(6);
//
//System.err.println("   ONE");
//		BidirectionalIteratorSTL<Integer> it = list.begin();
//		while(!it.isEnd()) {
//			System.err.println("value = "+it.getAndIncrement());
//		}
//System.err.println("   TWO");
//		list.sort();
//		it = list.begin();
//		while(!it.isEnd()) {
//			System.err.println("value = "+it.getAndIncrement());
//		}
//
//System.err.println("  THREE");
//		IteratorSTL<Integer> it2 = list.rBegin();
//		while(!it2.isEnd()) {
//			System.err.println("value = "+it2.getAndIncrement());
//		}
//
//		ListSTL<Integer> list2 = new ListSTL<Integer>();
//		list2.push_back(1000);
//		list2.push_back(1001);
//		list2.push_back(1002);
//		list2.push_back(1003);
//		list2.push_back(1004);
//
//		BidirectionalIteratorSTL<Integer> it3 = list2.begin();
//		it3.increment();
//		it3.increment();
//
//		list.splice( list.end(), list2, it3 );
//
//		System.err.println("old list");
//		IteratorSTL<Integer> it4 = list.begin();
//		while(!it4.isEnd()) {
//			System.err.println("value = "+it4.getAndIncrement());
//		}
//		System.err.println("new list");
//		it4 = list2.begin();
//		while(!it4.isEnd()) {
//			System.err.println("value = "+it4.getAndIncrement());
//		}
//
//		it3 = list2.begin();
//		it3.increment();
//		it3.increment();
//		System.err.println("it3 = "+it3.get());
//
//		list2.push_front(1002);
//		BidirectionalIteratorSTL<Integer> it5 = list2.begin();
//
//		System.err.println("pre-splice list");
//		it4 = list2.begin();
//		while(!it4.isEnd()) {
//			System.err.println("value = "+it4.getAndIncrement());
//		}
//
//		list2.splice( it3, list2, it5 );
//
//		System.err.println("repaired list");
//		it4 = list2.begin();
//		while(!it4.isEnd()) {
//			System.err.println("value = "+it4.getAndIncrement());
//		}
//
//	}


}
