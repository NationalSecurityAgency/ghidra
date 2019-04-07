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

import java.util.ArrayList;

public class VectorIterator<T> implements IteratorSTL<T> {
	protected int index;
	protected ArrayList<T> data;
	
	public VectorIterator(ArrayList<T> data, int index) {
		this.data = data;
		this.index = index;
	}
	
	@Override
	public String toString() {
	    T value = index >= data.size() ? null : data.get( index );
		return "VectorIterator: [index=" + index + " - " + value + "]"; 
	}
	
	public void assign( IteratorSTL<T> otherIterator ) {
		VectorIterator<T> other = (VectorIterator<T>) otherIterator;
		this.index = other.index;
		this.data = other.data;
	}
	public boolean isBegin() {
		return index == 0;
	}
	public boolean isEnd() {
		return index >= data.size();
	}
	public T get() {
		return data.get(index);
	}

	public void set(T value) {
		data.set(index, value);
	}

	public T get(int offset) {
		return data.get(index+offset);
	}

	public IteratorSTL<T> decrement() {
		if (index == 0) {
			throw new IndexOutOfBoundsException();
		}
		index--;
		return this;
	}


	public IteratorSTL<T> increment() {
		if (index >= data.size()) {
			throw new IndexOutOfBoundsException();
		}
		index++;
		return this;
	}

	public IteratorSTL<T> increment(int count) {
		if (index+count > data.size()) {
			throw new IndexOutOfBoundsException();
		}
		index += count;
		return this;
	}
	public IteratorSTL<T> decrement(int count) {
		if (index-count < 0) {
			throw new IndexOutOfBoundsException();
		}
		index -= count;
		return this;
	}
	
	
	public void insert(T value) {
		data.add(index, value);
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
		VectorIterator<?> other = (VectorIterator)obj;
		return data == other.data && index == other.index;
	}
	@Override
	public int hashCode() {
		return data.hashCode();
	}
	public IteratorSTL<T> copy() {
		return new VectorIterator<T>(data, index);
	}
	public int getIndex() {
		return index;
	}


}
