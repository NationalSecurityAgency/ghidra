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
package ghidra.trace.model;

import java.util.*;

import generic.Span;

/**
 * A closed range on snapshot keys, indicating a duration of time
 * 
 * <p>
 * To attempt to avoid overuse of boxed {@link Long}s, we add primitive getters for the endpoints
 * and re-define many of the interfaces' methods to work on those primitives directly. However,
 * we've not done any performance testing to know whether the juice is worth the squeeze.
 */
public sealed interface Lifespan extends Span<Long, Lifespan>, Iterable<Long> {
	Domain DOMAIN = Domain.INSTANCE;
	Empty EMPTY = Empty.INSTANCE;
	Impl ALL = new Impl(Long.MIN_VALUE, Long.MAX_VALUE);

	/**
	 * Get the lifespan for the given snap bounds
	 * 
	 * @param minSnap the minimum snap
	 * @param maxSnap the maximum snap
	 * @return the lifespan
	 */
	static Lifespan span(long minSnap, long maxSnap) {
		return DOMAIN.closed(minSnap, maxSnap);
	}

	/**
	 * Get the lifespan for only the given snap.
	 * 
	 * @param snap the snapshot key
	 * @return the lifespan
	 */
	static Lifespan at(long snap) {
		return DOMAIN.value(snap);
	}

	/**
	 * Get the lifespan from 0 to the given snap.
	 * 
	 * <p>
	 * The lower bound is 0 to exclude scratch space.
	 * 
	 * @param snap the snapshot key
	 * @return the lifespan
	 */
	static Lifespan since(long snap) {
		return new Impl(0, snap);
	}

	/**
	 * Get the lifespan from the given snap into the indefinite future
	 * 
	 * @param snap the snapshot key
	 * @return the lifespan
	 */
	static Lifespan nowOn(long snap) {
		return DOMAIN.atLeast(snap);
	}

	/**
	 * Get the lifespan from the given snap into the indefinite future, considering scratch space
	 * 
	 * <p>
	 * If the snapshot is in scratch space, then the span will have an upper endpoint of -1, the
	 * last scratch snapshot. Otherwise, this is the same as {@link #nowOn(long)}.
	 * 
	 * @param snap
	 * @return
	 */
	static Lifespan nowOnMaybeScratch(long snap) {
		if (isScratch(snap)) {
			return new Impl(snap, -1);
		}
		return new Impl(snap, Long.MAX_VALUE);
	}

	/**
	 * Check if a given snapshot key is designated as scratch space
	 * 
	 * <p>
	 * Conventionally, negative snaps are scratch space.
	 * 
	 * @param snap the snap
	 * @return true if scratch space
	 */
	public static boolean isScratch(long snap) {
		return snap < 0;
	}

	/**
	 * Get the lifespan from the given snap into the indefinite past, including scratch
	 * 
	 * @param snap the snapshot key
	 * @return the lifespan
	 */
	static Lifespan toNow(long snap) {
		return DOMAIN.atMost(snap);
	}

	/**
	 * Get the lifespan that excludes the given and all future snaps
	 * 
	 * @param snap the snap
	 * @return the lifespan
	 */
	static Lifespan before(long snap) {
		if (snap == DOMAIN.lmin()) {
			return EMPTY;
		}
		return DOMAIN.atMost(DOMAIN.dec(snap));
	}

	/**
	 * The domain of snapshot keys
	 */
	public enum Domain implements Span.Domain<Long, Lifespan> {
		INSTANCE;

		@Override
		public Lifespan closed(Long min, Long max) {
			return closed(min.longValue(), max.longValue());
		}

		public Lifespan closed(long min, long max) {
			if (max < min) {
				throw new IllegalArgumentException("max < min: min=" + min + ",max=" + max);
			}
			return new Impl(min, max);
		}

		@Override
		public Lifespan newSpan(Long min, Long max) {
			return new Impl(min, max);
		}

		public Lifespan value(long n) {
			return new Impl(n, n);
		}

		@Override
		public Lifespan atMost(Long max) {
			return atMost(max.longValue());
		}

		public Lifespan atMost(long max) {
			return new Impl(Long.MIN_VALUE, max);
		}

		@Override
		public Lifespan atLeast(Long min) {
			return atLeast(min.longValue());
		}

		public Lifespan atLeast(long min) {
			return new Impl(min, Long.MAX_VALUE);
		}

		@Override
		public Lifespan all() {
			return ALL;
		}

		@Override
		public Lifespan empty() {
			return EMPTY;
		}

		@Override
		public int compare(Long n1, Long n2) {
			return compare(n1.longValue(), n2.longValue());
		}

		public int compare(long n1, long n2) {
			return Long.compare(n1, n2);
		}

		@Override
		public Long min() {
			return lmin();
		}

		public long lmin() {
			return Long.MIN_VALUE;
		}

		@Override
		public Long max() {
			return lmax();
		}

		public long lmax() {
			return Long.MAX_VALUE;
		}

		@Override
		public Long inc(Long n) {
			return inc(n.longValue());
		}

		public long inc(long n) {
			return n + 1;
		}

		@Override
		public Long dec(Long n) {
			return dec(n.longValue());
		}

		public long dec(long n) {
			return n - 1;
		}

		public long min(long n1, long n2) {
			return Long.min(n1, n2);
		}

		public long max(long n1, long n2) {
			return Long.max(n1, n2);
		}

		@Override
		public Lifespan intersect(Lifespan s1, Lifespan s2) {
			if (!intersects(s1, s2)) {
				return empty();
			}
			return new Impl(max(s1.lmin(), s2.lmin()), min(s1.lmax(), s2.lmax()));
		}

		@Override
		public boolean intersects(Lifespan s1, Lifespan s2) {
			if (s1.isEmpty() || s2.isEmpty()) {
				return false;
			}
			return s1.lmax() >= s2.lmin() && s2.lmax() >= s1.lmin();
		}

		@Override
		public boolean encloses(Lifespan s1, Lifespan s2) {
			return s1.lmin() <= s2.lmin() && s2.lmax() <= s1.lmax();
		}

		@Override
		public Lifespan bound(Lifespan s1, Lifespan s2) {
			if (s1.isEmpty()) {
				return s2;
			}
			if (s2.isEmpty()) {
				return s1;
			}
			return new Impl(min(s1.lmin(), s2.lmin()), max(s1.lmax(), s2.lmax()));
		}
	}

	/**
	 * The singleton empty lifespan of snapshot keys
	 */
	public final class Empty implements Lifespan, Span.Empty<Long, Lifespan> {
		public static final Lifespan.Empty INSTANCE = new Lifespan.Empty();

		private Empty() {
		}

		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public long lmin() {
			throw new NoSuchElementException();
		}

		@Override
		public Long min() {
			throw new NoSuchElementException();
		}

		@Override
		public long lmax() {
			throw new NoSuchElementException();
		}

		@Override
		public Long max() {
			throw new NoSuchElementException();
		}

		@Override
		public boolean contains(long n) {
			return false;
		}

		@Override
		public boolean contains(Long n) {
			return false;
		}

		@Override
		public Iterator<Long> iterator() {
			return Collections.emptyIterator();
		}
	}

	/**
	 * A non-empty lifespan of snapshot keys
	 */
	public record Impl(long lmin, long lmax) implements Lifespan {
		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public boolean contains(long n) {
			return lmin <= n && n <= lmax;
		}

		@Override
		public boolean contains(Long n) {
			return lmin <= n && n <= lmax;
		}

		@Override
		public Long min() {
			return lmin;
		}

		@Override
		public Long max() {
			return lmax;
		}

		@Override
		public boolean minIsFinite() {
			return lmin != domain().lmin();
		}

		@Override
		public boolean maxIsFinite() {
			return lmax != domain().lmax();
		}

		@Override
		public Iterator<Long> iterator() {
			return new Iterator<>() {
				long val = lmin;

				@Override
				public boolean hasNext() {
					return val <= lmax;
				}

				@Override
				public Long next() {
					long next = val;
					val++;
					return next;
				}
			};
		}
	}

	/**
	 * A set of lifespans
	 */
	public interface LifeSet extends SpanSet<Long, Lifespan> {
	}

	/**
	 * A mutable set of lifespans
	 */
	public interface MutableLifeSet extends LifeSet, MutableSpanSet<Long, Lifespan> {
	}

	/**
	 * An interval tree implementing {@link MutableLifeSet}
	 */
	public class DefaultLifeSet extends DefaultSpanSet<Long, Lifespan> implements MutableLifeSet {
		public DefaultLifeSet() {
			super(Lifespan.DOMAIN);
		}
	}

	@Override
	default Domain domain() {
		return DOMAIN;
	}

	long lmin();

	long lmax();

	boolean contains(long n);

	default Lifespan withMin(long min) {
		return DOMAIN.closed(min, lmax());
	}

	default Lifespan withMax(long max) {
		return DOMAIN.closed(lmin(), max);
	}
}
