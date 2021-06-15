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

import org.apache.commons.collections4.collection.AbstractCollectionDecorator;

public class DefaultObservableCollection<E, L extends CollectionChangeListener<? super E>>
		extends AbstractCollectionDecorator<E> implements ObservableCollection<E, L> {

	protected enum Change {
		ADDED, REMOVED, MODIFIED;
		static Change then(Change one, Change two) {
			if (one == null) {
				return two;
			}
			assert two != null;
			switch (one) {
				case ADDED:
					switch (two) {
						case ADDED:
							assert false;
						case MODIFIED:
							return ADDED;
						case REMOVED:
							return null;
					}
				case MODIFIED:
					switch (two) {
						case ADDED:
							assert false;
						case MODIFIED:
							return MODIFIED;
						case REMOVED:
							return REMOVED;
					}
				case REMOVED:
					switch (two) {
						case ADDED:
							return MODIFIED;
						case MODIFIED:
							assert false;
						case REMOVED:
							assert false;
					}
			}
			throw new AssertionError("Unreachable");
		}
	}

	protected class ChangeSet implements CollectionChangeListener<E> {
		protected final Map<E, Change> changes = new LinkedHashMap<>();

		@Override
		public void elementAdded(E e) {
			synchronized (lock) {
				changes.compute(e, (b, c) -> Change.then(c, Change.ADDED));
			}
		}

		@Override
		public void elementModified(E e) {
			synchronized (lock) {
				changes.compute(e, (b, c) -> Change.then(c, Change.MODIFIED));
			}
		}

		@Override
		public void elementRemoved(E e) {
			synchronized (lock) {
				changes.compute(e, (b, c) -> Change.then(c, Change.REMOVED));
			}
		}

		protected void fire() {
			synchronized (lock) {
				for (Map.Entry<E, Change> ent : changes.entrySet()) {
					switch (ent.getValue()) {
						case ADDED:
							listeners.fire.elementAdded(ent.getKey());
							break;
						case REMOVED:
							listeners.fire.elementRemoved(ent.getKey());
							break;
						case MODIFIED:
							listeners.fire.elementModified(ent.getKey());
							break;
					}
				}
				changes.clear();
			}
		}
	}

	protected class DefaultChangeAggregator implements ChangeAggregator {
		public DefaultChangeAggregator() {
			aggregatorCount++;
			l = changes;
		}

		@Override
		public void close() {
			if (--aggregatorCount == 0) {
				l = listeners.fire;
				changes.fire();
			}
		}
	}

	protected final Object lock = new Object();
	protected final ListenerSet<L> listeners;
	protected final Collection<E> wrapped;
	protected int aggregatorCount = 0;
	protected final ChangeSet changes = new ChangeSet();
	protected CollectionChangeListener<? super E> l;

	protected DefaultObservableCollection(Collection<E> wrapped, Class<L> listenerClass) {
		this.wrapped = wrapped;
		this.listeners = new ListenerSet<>(listenerClass);
		this.l = this.listeners.fire;
	}

	@Override
	protected Collection<E> decorated() {
		return wrapped;
	}

	@Override
	public void addChangeListener(L listener) {
		listeners.add(listener);
	}

	@Override
	public void removeChangeListener(L listener) {
		listeners.remove(listener);
	}

	@Override
	public Iterator<E> iterator() {
		return new Iterator<E>() {
			Iterator<E> wit = wrapped.iterator();
			E last = null;

			@Override
			public boolean hasNext() {
				return wit.hasNext();
			}

			@Override
			public E next() {
				return last = wit.next();
			}

			@Override
			public void remove() {
				synchronized (lock) {
					wit.remove();
					notifyRemoved(last);
				}
			}
		};
	}

	@Override
	public boolean add(E e) {
		boolean result = wrapped.add(e);
		if (result) {
			notifyAdded(e);
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean remove(Object o) {
		boolean result = wrapped.remove(o);
		if (result) {
			notifyRemoved((E) o);
		}
		return result;
	}

	@Override
	public boolean addAll(Collection<? extends E> c) {
		boolean result = false;
		for (E e : c) {
			result |= add(e);
		}
		return result;
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		boolean result = false;
		for (Object o : c) {
			result |= remove(o);
		}
		return result;
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		boolean result = false;
		for (Iterator<E> it = iterator(); it.hasNext();) {
			E e = it.next();
			if (!c.contains(e)) {
				it.remove();
				result = true;
			}
		}
		return result;
	}

	@Override
	public void clear() {
		for (Iterator<E> it = iterator(); it.hasNext();) {
			it.next();
			it.remove();
		}
	}

	protected void notifyAdded(E e) {
		l.elementAdded(e);
	}

	@Override
	public void notifyModified(E e) {
		assert contains(e);
		l.elementModified(e);
	}

	protected void notifyRemoved(E e) {
		l.elementRemoved(e);
	}

	@Override
	public ChangeAggregator aggregateChanges() {
		return new DefaultChangeAggregator();
	}
}
