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
package generic;

import java.util.*;

public abstract class AbstractUnionedCollection<E> extends AbstractCollection<E> {
	protected final Collection<? extends Collection<? extends E>> collections;

	public AbstractUnionedCollection(Collection<? extends Collection<? extends E>> collections) {
		this.collections = collections;
	}

	@SafeVarargs
	public AbstractUnionedCollection(Collection<? extends E>... collections) {
		this.collections = Arrays.asList(collections);
	}

	@Override
	public int size() {
		int size = 0;
		for (Collection<? extends E> col : collections) {
			size += col.size();
		}
		return size;
	}

	@Override
	public boolean isEmpty() {
		for (Collection<? extends E> col : collections) {
			if (!col.isEmpty()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean contains(Object o) {
		for (Collection<? extends E> col : collections) {
			if (col.contains(o)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean remove(Object o) {
		for (Collection<? extends E> col : collections) {
			if (col.remove(o)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		boolean result = false;
		for (Collection<? extends E> col : collections) {
			result |= col.removeAll(c);
		}
		return result;
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		boolean result = false;
		for (Collection<? extends E> col : collections) {
			result |= col.retainAll(c);
		}
		return result;
	}

	@Override
	public void clear() {
		for (Collection<? extends E> col : collections) {
			col.clear();
		}
	}
}
