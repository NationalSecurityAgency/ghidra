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
package generic.stl;

class ReverseListIterator<T> extends ListIterator<T> {

	ReverseListIterator(ListSTL<T> list, ListNodeSTL<T> root, ListNodeSTL<T> node) {
		super(list, root, node);
	}
	
	@Override
    public IteratorSTL<T> copy() {
		return new ReverseListIterator<T>( list, root, node );
	}

	@Override
    public boolean isBegin() {
		return node == root.prev;
	}
	
	@Override
    public IteratorSTL<T> decrement() {
		if (node.prev == root) {
			throw new IndexOutOfBoundsException();
		}
		node = node.next;
		return this;
	}

	@Override
    public IteratorSTL<T> increment() {
		node = node.prev;
		return this;
	}

	@Override
    public void insert(T value) {
		ListNodeSTL<T> newNode = new ListNodeSTL<T>(node, node.next, value);
		node.next.prev = newNode;
		node.next = newNode;
		node = newNode;
		list.adjustSize(1);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != this.getClass()) {
			return false;
		}
		ReverseListIterator<?> other = (ReverseListIterator)obj;
		return list == other.list && node == other.node;
	}
	@Override
	public int hashCode() {
		return list.hashCode();
	}

}
