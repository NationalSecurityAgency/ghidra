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

import java.util.*;

class ReverseVectorIterator<T> extends VectorIterator<T> {
	public ReverseVectorIterator(ArrayList<T> data, int index) {
		super(data, index);
	}
	@Override
    public boolean isBegin() {
		return index == (data.size()-1);
	}
	@Override
    public boolean isEnd() {
		return index < 0;
	}

	@Override
    public T get(int offset) {
		return data.get(index-offset);
	}

	@Override
    public IteratorSTL<T> decrement() {
		if (index == data.size()-1) {
			throw new IndexOutOfBoundsException();
		}
		index++;
		return this;
	}

	public void delete(int count) {
		if (index < count-1) {
			throw new IndexOutOfBoundsException();
		}
		data.subList(index-count+1, count).clear();
	}

	@Override
    public IteratorSTL<T> increment() {
		if (index < 0) {
			throw new IndexOutOfBoundsException();
		}
		index--;
		return this;
	}

	@Override
    public IteratorSTL<T> increment(int count) {
		if (index-count < -1) {
			throw new IndexOutOfBoundsException();
		}
		index -= count;
		return this;
	}
	@Override
    public IteratorSTL<T> decrement(int count) {
		if (index+count >= data.size()) {
			throw new IndexOutOfBoundsException();
		}
		index += count;
		return this;
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
		ReverseVectorIterator<?> other = (ReverseVectorIterator)obj;
		return data == other.data && index == other.index;
	}
	@Override
	public int hashCode() {
		return data.hashCode();
	}
	
	@Override
    public IteratorSTL<T> copy() {
		return new ReverseVectorIterator<T>(data, index);
	}
	
	@Override
    public int getIndex() {
		return index;
	}


}
