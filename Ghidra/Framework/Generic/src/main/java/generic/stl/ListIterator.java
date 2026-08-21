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

public class ListIterator<T> implements IteratorSTL<T> {
	ListSTL<T> list;
	ListNodeSTL<T> root;
	protected ListNodeSTL<T> node;
	public StackTraceElement[] stackUse;
	

	ListIterator(ListSTL<T> list, ListNodeSTL<T> root, ListNodeSTL<T> node) {
		this.list = list;
		this.root = root;
		this.node = node;
	}
	
	@Override
	public void assign( IteratorSTL<T> otherIterator ) {
		ListIterator<T> other = (ListIterator<T>)otherIterator;
		this.list = other.list;
		this.root = other.root;
		this.node = other.node;
	}
	@Override
	public IteratorSTL<T> copy() {
		return new ListIterator<T>( list, root, node );
	}

	@Override
	public boolean isBegin() {
		return node == root.next;
	}

	@Override
	public boolean isEnd() {
		return node == root;
	}
	
	
	@Override
	public IteratorSTL<T> decrement() {
		if (node.prev == root) {
			throw new IndexOutOfBoundsException();
		}
		node = node.prev;
		return this;
	}

	@Override
	public T get() {
		if (node == root) {
			throw new IndexOutOfBoundsException();
		}
		return node.value;
	}

	@Override
	public IteratorSTL<T> increment() {
		node = node.next;
		return this;
	}

	@Override
	public IteratorSTL<T> increment(int count) {
		for(int i=0;i<count;i++) {
			increment();
		}
		return this;
	}
	@Override
	public IteratorSTL<T> decrement( int n ) {
		throw new UnsupportedOperationException();
	}
	@Override
	public void insert(T value) {
		ListNodeSTL<T> newNode = new ListNodeSTL<T>(node.prev, node, value);
		node.prev.next = newNode;
		node.prev = newNode;
		node = newNode;
		list.adjustSize(1);
	}

	@Override
	public void set(T value) {
		if (root == node) {
			throw new IndexOutOfBoundsException();
		}
		node.value = value;
	}

	protected ListNodeSTL<T> getNode(){
		return node;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof ListIterator)) {
			return false;
		}
		ListIterator<?> other = (ListIterator)obj;
		return list == other.list && node == other.node;
	}
	@Override
	public int hashCode() {
		return list.hashCode();
	}

}
