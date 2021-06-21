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
package ghidra.util.database.spatial;

import java.lang.reflect.Array;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Consumer;

import com.google.common.collect.Iterators;

import ghidra.util.LockHold;
import ghidra.util.database.spatial.DBTreeDataRecord.RecordEntry;

public abstract class AbstractConstraintsTreeSpatialMap< //
		DS extends BoundedShape<NS>, //
		DR extends DBTreeDataRecord<DS, NS, T>, //
		NS extends BoundingShape<NS>, //
		T, //
		Q extends Query<DS, NS>> //
		implements SpatialMap<DS, T, Q> {

	protected final AbstractConstraintsTree<DS, DR, NS, ?, T, Q> tree;
	protected final Q query;

	public AbstractConstraintsTreeSpatialMap(AbstractConstraintsTree<DS, DR, NS, ?, T, Q> tree,
			Q query) {
		this.tree = tree;
		this.query = query;
	}

	@Override
	public T put(DS shape, T value) {
		try (LockHold hold = LockHold.lock(tree.dataStore.writeLock())) {
			DBTreeDataRecord<DS, NS, T> record = tree.doInsertData(shape, value);
			return record.getRecordValue();
		}
	}

	@Override
	public boolean remove(DS shape, T value) {
		try (LockHold hold = LockHold.lock(tree.dataStore.writeLock())) {
			return tree.doRemoveData(shape, value, query);
		}
	}

	@Override
	public boolean remove(Entry<DS, T> entry) {
		try (LockHold hold = LockHold.lock(tree.dataStore.writeLock())) {
			if (!(entry instanceof RecordEntry)) {
				return tree.doRemoveData(entry.getKey(), entry.getValue(), query);
			}
			@SuppressWarnings("rawtypes")
			DBTreeDataRecord rec = ((RecordEntry) entry).asRecord();
			// TODO: Should probably just if rec's store is tree.dataStore
			if (!tree.dataStore.asMap().containsValue(rec)) {
				return tree.doRemoveData(entry.getKey(), entry.getValue(), query);
			}
			@SuppressWarnings("unchecked")
			DR dr = (DR) rec;
			tree.doDeleteEntry(dr);
			return true;
		}
	}

	@Override
	public int size() {
		try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
			return tree.count(query);
		}
	}

	@Override
	public boolean isEmpty() {
		try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
			return tree.isEmpty(query);
		}
	}

	protected static int checkInt(long l) {
		if (l > Integer.MAX_VALUE) {
			throw new IllegalArgumentException();
		}
		return (int) l;
	}

	protected static class SynchronizedIterator<T> implements Iterator<T> {
		private final Iterator<T> iterator;
		private final ReadWriteLock lock;

		public SynchronizedIterator(Iterator<T> iterator, ReadWriteLock lock) {
			this.iterator = iterator;
			this.lock = lock;
		}

		@Override
		public boolean hasNext() {
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				return iterator.hasNext();
			}
		}

		@Override
		public T next() {
			try (LockHold hold = LockHold.lock(lock.readLock())) {
				return iterator.next();
			}
		}

		@Override
		public void remove() {
			try (LockHold hold = LockHold.lock(lock.writeLock())) {
				iterator.remove();
			}
		}
	}

	protected abstract static class ToArrayConsumer<A, T, U extends A> implements Consumer<T> {
		protected final A[] arr;
		protected int i = 0;

		public ToArrayConsumer(A[] arr) {
			this.arr = arr;
		}

		@Override
		public void accept(T t) {
			arr[i++] = transformed(t);
		}

		protected abstract U transformed(T t);

		protected void putNull() {
			if (i < arr.length) {
				arr[i] = null;
			}
		}
	}

	protected abstract static class ToListConsumer<A, T, U extends A> implements Consumer<T> {
		protected final List<A> list;

		public ToListConsumer(List<A> list) {
			this.list = list;
		}

		@Override
		public void accept(T t) {
			list.add(transformed(t));
		}

		protected abstract U transformed(T t);
	}

	@Override
	public Collection<Entry<DS, T>> entries() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<Entry<DS, T>> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.iterator(query), r -> r.asEntry()),
						tree.dataStore.getLock());
				}
			}

			public Object[] toArray() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					// Note, computing size requires a traversal. Bad idea, I think.
					List<Entry<DS, T>> result = new ArrayList<>();
					tree.visitAllData(query, new ToListConsumer<>(result) {
						@Override
						protected Entry<DS, T> transformed(DR t) {
							return t.asEntry();
						}
					}, false);
					return result.toArray();
				}
			}

			@SuppressWarnings("unchecked")
			public <U> U[] toArray(U[] a) {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					int size = AbstractConstraintsTreeSpatialMap.this.size();
					if (a.length < size) {
						a = (U[]) Array.newInstance(a.getClass().getComponentType(), size);
					}
					ToArrayConsumer<U, DR, U> consumer = new ToArrayConsumer<>(a) {
						@Override
						protected U transformed(DR t) {
							return (U) t.asEntry();
						}
					};
					tree.visitAllData(query, consumer, false);
					consumer.putNull();
					return a;
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Collection<Entry<DS, T>> orderedEntries() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<Entry<DS, T>> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.orderedIterator(query), r -> r.asEntry()),
						tree.dataStore.getLock());
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Collection<DS> keys() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<DS> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.iterator(query), r -> r.getShape()),
						tree.dataStore.getLock());
				}
			}

			public Object[] toArray() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					List<DS> result = new ArrayList<>();
					tree.visitAllData(query, new ToListConsumer<>(result) {
						@Override
						protected DS transformed(DR t) {
							return t.getShape();
						}
					}, false);
					return result.toArray();
				}
			}

			@SuppressWarnings("unchecked")
			public <U> U[] toArray(U[] a) {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					int size = AbstractConstraintsTreeSpatialMap.this.size();
					if (a.length < size) {
						a = (U[]) Array.newInstance(a.getClass().getComponentType(), size);
					}
					ToArrayConsumer<U, DR, U> consumer = new ToArrayConsumer<>(a) {
						@Override
						protected U transformed(DR t) {
							return (U) t.getShape();
						}
					};
					tree.visitAllData(query, consumer, false);
					consumer.putNull();
					return a;
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Collection<DS> orderedKeys() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<DS> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.orderedIterator(query), r -> r.getShape()),
						tree.dataStore.getLock());
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Collection<T> values() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<T> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.iterator(query), r -> r.getRecordValue()),
						tree.dataStore.getLock());
				}
			}

			public Object[] toArray() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					List<T> result = new ArrayList<>();
					tree.visitAllData(query, new ToListConsumer<>(result) {
						@Override
						protected T transformed(DR t) {
							return t.getRecordValue();
						}
					}, false);
					return result.toArray();
				}
			}

			@SuppressWarnings("unchecked")
			public <U> U[] toArray(U[] a) {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					int size = AbstractConstraintsTreeSpatialMap.this.size();
					if (a.length < size) {
						a = (U[]) Array.newInstance(a.getClass().getComponentType(), size);
					}
					ToArrayConsumer<U, DR, U> consumer = new ToArrayConsumer<>(a) {
						@Override
						protected U transformed(DR t) {
							return (U) t.getRecordValue();
						}
					};
					tree.visitAllData(query, consumer, false);
					consumer.putNull();
					return a;
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Collection<T> orderedValues() {
		return new AbstractCollection<>() {
			@Override
			public Iterator<T> iterator() {
				try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
					return new SynchronizedIterator<>(
						Iterators.transform(tree.orderedIterator(query),
							r -> r.getRecordValue()),
						tree.dataStore.getLock());
				}
			}

			@Override
			public int size() {
				return checkInt(AbstractConstraintsTreeSpatialMap.this.size());
			}

			@Override
			public boolean isEmpty() {
				return AbstractConstraintsTreeSpatialMap.this.isEmpty();
			}
		};
	}

	@Override
	public Entry<DS, T> firstEntry() {
		try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
			DBTreeDataRecord<DS, NS, T> first = tree.first(query);
			return first == null ? null : first.asEntry();
		}
	}

	@Override
	public DS firstKey() {
		try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
			DBTreeDataRecord<DS, NS, T> first = tree.first(query);
			return first == null ? null : first.getShape();
		}
	}

	@Override
	public T firstValue() {
		try (LockHold hold = LockHold.lock(tree.dataStore.readLock())) {
			DBTreeDataRecord<DS, NS, T> first = tree.first(query);
			return first == null ? null : first.getRecordValue();
		}
	}

	@Override
	public void clear() {
		try (LockHold hold = LockHold.lock(tree.dataStore.writeLock())) {
			tree.clear(query);
		}
	}
}
