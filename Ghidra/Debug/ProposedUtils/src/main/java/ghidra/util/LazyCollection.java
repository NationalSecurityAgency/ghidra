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
package ghidra.util;

import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

import javax.help.UnsupportedOperationException;

public class LazyCollection<T> implements Collection<T> {
	private final Supplier<Stream<? extends T>> streamFactory;

	public LazyCollection(Supplier<Stream<? extends T>> streamFactory) {
		this.streamFactory = streamFactory;
	}

	@Override
	public int size() {
		return (int) streamFactory.get().count();
	}

	@Override
	public boolean isEmpty() {
		return streamFactory.get().findAny().isEmpty();
	}

	@Override
	public boolean contains(Object o) {
		return streamFactory.get().anyMatch(e -> Objects.equals(e, o));
	}

	@Override
	@SuppressWarnings("unchecked")
	public Iterator<T> iterator() {
		return (Iterator<T>) streamFactory.get().iterator();
	}

	@Override
	public Object[] toArray() {
		return streamFactory.get().toArray();
	}

	@Override
	public <U> U[] toArray(U[] a) {
		return streamFactory.get().toList().toArray(a);
	}

	@Override
	public boolean add(T e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(Object o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		Set<?> remains = new HashSet<>(c);
		return remains.isEmpty() || streamFactory.get().anyMatch(e -> {
			remains.remove(e);
			return remains.isEmpty();
		});
	}

	@Override
	public boolean addAll(Collection<? extends T> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}
}
