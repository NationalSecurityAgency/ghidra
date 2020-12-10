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
package ghidra.trace.database.space;

import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.function.*;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.util.LockHold;

public interface DBTraceDelegatingManager<M> {
	interface ExcFunction<T, R, E1 extends Throwable, E2 extends Throwable> {
		R apply(T t) throws E1, E2;
	}

	interface ExcConsumer<T, E1 extends Throwable, E2 extends Throwable> {
		void accept(T t) throws E1, E2;
	}

	interface ExcPredicate<T, E1 extends Throwable, E2 extends Throwable> {
		boolean test(T t) throws E1, E2;
	}

	default void checkIsInMemory(AddressSpace space) {
		if (!space.isMemorySpace()) {
			throw new IllegalArgumentException("Address must be in memory");
		}
	}

	default <T, E1 extends Throwable, E2 extends Throwable> T delegateWrite(AddressSpace space,
			ExcFunction<M, T, E1, E2> func) throws E1, E2 {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(writeLock())) {
			M m = getForSpace(space, true);
			return func.apply(m);
		}
	}

	default <E1 extends Throwable, E2 extends Throwable> void delegateWriteV(AddressSpace space,
			ExcConsumer<M, E1, E2> func) throws E1, E2 {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(writeLock())) {
			M m = getForSpace(space, true);
			func.accept(m);
		}
	}

	default int delegateWriteI(AddressSpace space, ToIntFunction<M> func) {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(writeLock())) {
			M m = getForSpace(space, true);
			return func.applyAsInt(m);
		}
	}

	default <E1 extends Throwable, E2 extends Throwable> void delegateWriteAll(Iterable<M> spaces,
			ExcConsumer<M, E1, E2> func) throws E1, E2 {
		try (LockHold hold = LockHold.lock(writeLock())) {
			for (M m : spaces) {
				func.accept(m);
			}
		}
	}

	default <T, E1 extends Throwable, E2 extends Throwable> T delegateRead(AddressSpace space,
			ExcFunction<M, T, E1, E2> func) throws E1, E2 {
		return delegateRead(space, func, null);
	}

	default <T, E1 extends Throwable, E2 extends Throwable> T delegateRead(AddressSpace space,
			ExcFunction<M, T, E1, E2> func, T ifNull) throws E1, E2 {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(space, false);
			if (m == null) {
				return ifNull;
			}
			return func.apply(m);
		}
	}

	default int delegateReadI(AddressSpace space, ToIntFunction<M> func, int ifNull) {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(space, false);
			if (m == null) {
				return ifNull;
			}
			return func.applyAsInt(m);
		}
	}

	default boolean delegateReadB(AddressSpace space, Predicate<M> func, boolean ifNull) {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(readLock())) {
			M m = getForSpace(space, false);
			if (m == null) {
				return ifNull;
			}
			return func.test(m);
		}
	}

	default <E1 extends Throwable> void delegateDeleteV(AddressSpace space,
			ExcConsumer<M, E1, E1> func) throws E1 {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(writeLock())) {
			M m = getForSpace(space, false);
			if (m == null) {
				return;
			}
			func.accept(m);
		}
	}

	default boolean delegateDeleteB(AddressSpace space, Predicate<M> func, boolean ifNull) {
		checkIsInMemory(space);
		try (LockHold hold = LockHold.lock(writeLock())) {
			M m = getForSpace(space, false);
			if (m == null) {
				return ifNull;
			}
			return func.test(m);
		}
	}

	default <T> T delegateFirst(Iterable<M> spaces, Function<M, T> func) {
		try (LockHold hold = LockHold.lock(readLock())) {
			for (M m : spaces) {
				T t = func.apply(m);
				if (t != null) {
					return t;
				}
			}
			return null;
		}
	}

	/**
	 * Compose a collection, lazily, from collections returned by delegates
	 * 
	 * @param spaces the delegates
	 * @param func a collection getter for each delegate
	 * @return the lazy catenated collection
	 */
	default <T> Collection<T> delegateCollection(Iterable<M> spaces,
			Function<M, Collection<T>> func) {
		return new AbstractCollection<>() {
			@Override
			public Iterator<T> iterator() {
				return NestedIterator.start(spaces.iterator(), func.andThen(Iterable::iterator));
			}

			@Override
			public int size() {
				try (LockHold hold = LockHold.lock(readLock())) {
					int sum = 0;
					for (M m : spaces) {
						sum += func.apply(m).size();
					}
					return sum;
				}
			}

			public boolean isEmpty() {
				try (LockHold hold = LockHold.lock(readLock())) {
					for (M m : spaces) {
						if (!func.apply(m).isEmpty()) {
							return false;
						}
					}
					return true;
				}
			}
		};
	}

	/**
	 * Compose a set, immediately, from collections returned by delegates
	 * 
	 * @param spaces the delegates
	 * @param func a collection (usually a set) getter for each delegate
	 * @return the unioned results
	 */
	default <T> HashSet<T> delegateHashSet(Iterable<M> spaces, Function<M, Collection<T>> func) {
		try (LockHold hold = LockHold.lock(readLock())) {
			HashSet<T> result = new HashSet<>();
			for (M m : spaces) {
				result.addAll(func.apply(m));
			}
			return result;
		}
	}

	/**
	 * Compose an address set, immediately, from address sets returned by delegates
	 * 
	 * @param spaces the delegates
	 * @param func an address set getter for each delegate
	 * @return the unioned results
	 */
	default <E1 extends Throwable, E2 extends Throwable> AddressSetView delegateAddressSet(
			Iterable<M> spaces, ExcFunction<M, AddressSetView, E1, E2> func) throws E1, E2 {
		try (LockHold hold = LockHold.lock(readLock())) {
			AddressSet result = new AddressSet();
			for (M m : spaces) {
				result.add(func.apply(m));
			}
			return result;
		}
	}

	default <E1 extends Throwable, E2 extends Throwable> boolean delegateAny(Iterable<M> spaces,
			ExcPredicate<M, E1, E2> func) throws E1, E2 {
		try (LockHold hold = LockHold.lock(readLock())) {
			for (M m : spaces) {
				if (func.test(m)) {
					return true;
				}
			}
			return false;
		}
	}

	Lock readLock();

	Lock writeLock();

	M getForSpace(AddressSpace space, boolean createIfAbsent);
}
