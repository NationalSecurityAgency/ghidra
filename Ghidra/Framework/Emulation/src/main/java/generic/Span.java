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
import java.util.Map.Entry;
import java.util.stream.Collectors;

import generic.ULongSpan.*;

/**
 * A (closed) interval
 *
 * <p>
 * An interval-like type may implement this interface in order to obtain a near out-of-box
 * implementation of a map and/or set of spans. Common operations, such as computing intersections
 * and bounds, are provided. Similarly, spans are automatically coalesced when present in sets and
 * maps. The main requirement is that the span define the domain of its endpoints. The domain can
 * impose behaviors and properties that aren't otherwise present on the type of endpoints. For
 * example, the domain may be {@link Long}s, but using unsigned attributes. The domain also provides
 * a factory for new spans. While nominally, this only supports closed intervals, the domain can
 * define a custom endpoint type to obtain mixed intervals, as in {@link End}.
 *
 * @param <N> the type of endpoints
 * @param <S> the type of spans (recursive)
 */
public interface Span<N, S extends Span<N, S>> extends Comparable<S> {
	/**
	 * The (discrete) domain of endpoints for a span
	 *
	 * <p>
	 * This defines the domain, which may introduce behaviors different than those naturally
	 * acquired from the type. For example, a domain may impose unsigned comparison on a (boxed)
	 * primitive type.
	 *
	 * @implNote each domain should be a singleton class
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 */
	public interface Domain<N, S extends Span<N, S>> {
		/**
		 * Create a new span with the given endpoints, inclusive.
		 * 
		 * @param min the lower endpoint
		 * @param max the upper endpoint
		 * @return the span
		 * @throws IllegalArgumentException if max is less than min
		 */
		default S closed(N min, N max) {
			if (compare(min, max) > 0) {
				throw new IllegalArgumentException("min > max: min=" + min + ",max=" + max);
			}
			return newSpan(min, max);
		}

		/**
		 * Factory method for a new span after arguments are validated
		 * 
		 * @param min the lower endpoint
		 * @param max the upper endpoint
		 * @return the span
		 */
		S newSpan(N min, N max);

		/**
		 * Construct a span containing only the given value
		 * 
		 * @param n the value
		 * @return the span
		 */
		default S value(N n) {
			return closed(n, n);
		}

		/**
		 * Construct a new span with the given upper endpoint, inclusive.
		 * 
		 * <p>
		 * The lower endpoint becomes the minimum value in the domain
		 * 
		 * @param max the upper endpoint
		 * @return the span
		 */
		default S atMost(N max) {
			return closed(min(), max);
		}

		/**
		 * Construct a new span with the given lower endpoint, inclusive.
		 * 
		 * <p>
		 * The upper endpoint becomes the maximum value in the domain
		 * 
		 * @param min the lower endpoint
		 * @return the span
		 */
		default S atLeast(N min) {
			return closed(min, max());
		}

		/**
		 * Get the span containing all values in the domain
		 * 
		 * @implNote It is recommended to return a static object
		 * @return the span
		 */
		S all();

		/**
		 * Get the span that contains no value, nor has any endpoints
		 * 
		 * <p>
		 * This span is returned when the result doesn't exist, e.g., when finding the intersection
		 * of spans which do not intersect.
		 * 
		 * @implNote It is recommended to implement {@link Empty} as a singleton class and return
		 *           its instance
		 * @return the empty span
		 */
		S empty();

		/**
		 * Render the given value as a string
		 * 
		 * @param n the value
		 * @return the string
		 */
		default String toString(N n) {
			return n.toString();
		}

		/**
		 * Render the given span as a string
		 * 
		 * @param s the span
		 * @return the string
		 */
		default String toString(S s) {
			return s.isEmpty() ? "(empty)" : toMinString(s.min()) + ".." + toMaxString(s.max());
		}

		/**
		 * Render the lower bound of a span
		 * 
		 * @param min the lower bound
		 * @return the string
		 */
		default String toMinString(N min) {
			return min().equals(min) ? "(-inf" : ("[" + toString(min));
		}

		/**
		 * Render the upper bound of a span
		 * 
		 * @param max the upper bound
		 * @return the string
		 */
		default String toMaxString(N max) {
			return max().equals(max) ? "+inf)" : (toString(max) + "]");
		}

		/**
		 * Compare two values
		 * 
		 * @param n1 a value
		 * @param n2 another value
		 * @return the result, as in {@link Comparator#compare(Object, Object)}
		 */
		int compare(N n1, N n2);

		/**
		 * Get the minimum value in the domain
		 * 
		 * <p>
		 * This value can also represent negative infinity.
		 * 
		 * @return the minimum value
		 */
		N min();

		/**
		 * Get the maximum value in the domain
		 * 
		 * <p>
		 * This value can also represent positive infinity.
		 * 
		 * @return the maximum value
		 */
		N max();

		/**
		 * Get a given value, incremented by 1
		 * 
		 * <p>
		 * If the resulting value would exceed {@link #max()}, this should wrap to {@link #min()}.
		 * 
		 * @param n the value
		 * @return the value incremented
		 */
		N inc(N n);

		/**
		 * Get a given value, decremented by 1
		 * 
		 * <p>
		 * If the resulting value would exceed {@link #min()}, this should wrap to {@link #max()}.
		 * 
		 * @param n the value
		 * @return the value decremented
		 */
		N dec(N n);

		/**
		 * Get the lesser of two values
		 * 
		 * <p>
		 * If the values are equal, then either may be chosen
		 * 
		 * @param n1 a value
		 * @param n2 another value
		 * @return the lesser
		 */
		default N min(N n1, N n2) {
			return compare(n1, n2) < 0 ? n1 : n2;
		}

		/**
		 * Get the greater of two values
		 * 
		 * <p>
		 * If the values are equal, then either may be chosen
		 * 
		 * @param n1 a value
		 * @param n2 another value
		 * @return the greater
		 */
		default N max(N n1, N n2) {
			return compare(n1, n2) < 0 ? n2 : n1;
		}

		/**
		 * Compute the intersection of two spans
		 * 
		 * @param s1 a span
		 * @param s2 another span
		 * @return the intersection, possibly empty
		 */
		default S intersect(S s1, S s2) {
			if (!intersects(s1, s2)) {
				return empty();
			}
			return closed(max(s1.min(), s2.min()), min(s1.max(), s2.max()));
		}

		/**
		 * Check if two spans intersect
		 * 
		 * @param s1 a span
		 * @param s2 another span
		 * @return true if they intersect
		 */
		default boolean intersects(S s1, S s2) {
			if (s1.isEmpty() || s2.isEmpty()) {
				return false;
			}
			return compare(s1.max(), s2.min()) >= 0 && compare(s2.max(), s1.min()) >= 0;
		}

		/**
		 * Check if one span encloses another
		 * 
		 * @param s1 a span
		 * @param s2 another span
		 * @return true if s1 encloses s2
		 */
		default boolean encloses(S s1, S s2) {
			if (s1.isEmpty()) {
				return false;
			}
			if (s2.isEmpty()) {
				return true;
			}
			return compare(s1.min(), s2.min()) <= 0 && compare(s1.max(), s2.max()) >= 0;
		}

		/**
		 * Compute the smallest span which contains two spans
		 * 
		 * @param s1 a span
		 * @param s2 another span
		 * @return the bounding span
		 */
		default S bound(S s1, S s2) {
			if (s1.isEmpty()) {
				return s2;
			}
			if (s2.isEmpty()) {
				return s1;
			}
			return closed(min(s1.min(), s2.min()), max(s1.max(), s2.max()));
		}

		/**
		 * Subtract two spans
		 * 
		 * <p>
		 * If the first span is empty, this returns 0 spans.
		 * 
		 * @param s1 a span
		 * @param s2 another span
		 * @return 0, 1, or 2 spans
		 */
		default List<S> subtract(S s1, S s2) {
			if (s1.isEmpty()) {
				return List.of();
			}
			if (s2.isEmpty()) {
				return List.of(s1);
			}
			if (compare(s1.max(), s2.min()) < 0 || compare(s2.max(), s1.min()) < 0) {
				return List.of(s1);
			}
			if (compare(s1.min(), s2.min()) < 0) {
				if (compare(s1.max(), s2.max()) > 0) {
					return List.of(
						closed(s1.min(), dec(s2.min())),
						closed(inc(s2.max()), s1.max()));
				}
				return List.of(closed(s1.min(), dec(s2.min())));
			}
			if (compare(s1.max(), s2.max()) > 0) {
				return List.of(closed(inc(s2.max()), s1.max()));
			}
			return List.of();
		}
	}

	/**
	 * A mix-in interface for empty spans
	 *
	 * @implNote It is recommended to implement this as a singleton class
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 */
	public interface Empty<N, S extends Span<N, S>> extends Span<N, S> {
		@Override
		default N min() {
			throw new NoSuchElementException();
		}

		@Override
		default N max() {
			throw new NoSuchElementException();
		}

		@Override
		default boolean isEmpty() {
			return true;
		}

		@Override
		default boolean contains(N c) {
			return false;
		}
	}

	/**
	 * An abstract interface for an immutable map of spans to values
	 * 
	 * <p>
	 * Spans are not allowed to overlap, and connected spans are automatically coalesced when mapped
	 * to the same value. For example, the entries {@code [1..5]='A'} and {@code [6..10]='A'} become
	 * one entry {@code [1..10]='A'}. When an entry is added that overlaps other entries, the
	 * existing entries are truncated or deleted (or coalesced if they share the same value as the
	 * new entry) so that the new entry can fit.
	 * 
	 * @implNote It is recommended to create an interface (having only the {@link V} parameter)
	 *           extending this one specific to your domain and span type, then implement it using
	 *           an extension of {@link DefaultSpanMap}. See {@link ULongSpanMap} for an example.
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 * @param <V> the type of values
	 */
	public interface SpanMap<N, S extends Span<N, S>, V> {
		/**
		 * Check if this map has any entries
		 * 
		 * @return true if empty
		 */
		boolean isEmpty();

		/**
		 * Get the spans in this map
		 * 
		 * <p>
		 * Note that the behavior regarding a copy versus a view is not specified. Clients should
		 * not rely on one or the other.
		 * 
		 * @return the set of spans
		 */
		Set<S> spans();

		/**
		 * Get the values in this map
		 * 
		 * <p>
		 * Note that the behavior regarding a copy versus a view is not specified. Clients should
		 * not rely on one of the other.
		 * 
		 * @return the collection of values
		 */
		Collection<V> values();

		/**
		 * Get a span which encloses all spans in the map
		 * 
		 * @return the bounding span
		 */
		S bound();

		/**
		 * Get the entries in this map
		 * <p>
		 * Note that the behavior regarding a copy versus a view is not specified. Clients should
		 * not rely on one or the other.
		 * 
		 * @return the set of entries
		 */
		Set<Map.Entry<S, V>> entries();

		/**
		 * Get the entry whose span contains the given key
		 * 
		 * @param n the key
		 * @return the entry, or null
		 */
		Map.Entry<S, V> getEntry(N n);

		/**
		 * Get the value of the given key
		 * 
		 * <p>
		 * Note that a null return could indicate either that no entry has a span containing the
		 * given key, or that the entry whose span contains it has the null value. To distinguish
		 * the two, consider using {@link #getEntry(Object)}.
		 * 
		 * @param n the key
		 * @return the value, or null
		 */
		V get(N n);

		/**
		 * Iterate over all entries whose spans intersect the given span
		 * 
		 * @param s the span
		 * @return an iterable of entries
		 */
		Iterable<Map.Entry<S, V>> intersectingEntries(S s);

		/**
		 * Iterate over all spans in the map that intersect the given span
		 * 
		 * @param s the span
		 * @return an iterable of spans
		 */
		Iterable<S> intersectingSpans(S s);

		/**
		 * Check if any span in the map intersects the given span
		 * 
		 * @param s the span
		 * @return true if any span in the map intersects it
		 */
		boolean intersects(S s);
	}

	/**
	 * An abstract interface for a mutable {@link SpanMap}
	 *
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 * @param <V> the type of values
	 */
	public interface MutableSpanMap<N, S extends Span<N, S>, V> extends SpanMap<N, S, V> {
		/**
		 * Put an entry, mapping all keys contains in the span to the given value
		 * 
		 * <p>
		 * Each key can only be mapped to a single value. Thus existing entries having the same
		 * value may be coalesced to this new entry. Existing entries having a different value will
		 * be truncated or deleted to make room for this entry.
		 * 
		 * @param s the span
		 * @param v the value
		 */
		void put(S s, V v);

		/**
		 * Copy all entries from the given map into this one
		 * 
		 * <p>
		 * The entries from both maps may be coalesced when entered into this one. (The given map
		 * remains unmodified.) The entries in this map may be truncated or deleted to make room for
		 * those in the given map.
		 * 
		 * @param map the other map
		 */
		void putAll(SpanMap<N, S, V> map);

		/**
		 * Delete all keys in the given span
		 * 
		 * <p>
		 * Entries which intersect the given span are truncated. Entries which are enclosed are
		 * deleted, such that every key in the given span is no longer mapped to a value.
		 * 
		 * @param s the span
		 */
		void remove(S s);

		/**
		 * Remove all entries from the map
		 */
		void clear();
	}

	/**
	 * An abstract interface for a set of spans
	 *
	 * <p>
	 * Connected spans in the set are automatically coalesced. For example, the set
	 * {@code [[0..5],[6..10]]} becomes {@code [[0..10]]}.
	 * 
	 * @implNote It is recommended to create an unparameterized interface extending this one
	 *           specific to your domain and span type, then implement it using an extension of
	 *           {@link DefaultSpanSet}. See {@link ULongSpanSet} for an example.
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 */
	public interface SpanSet<N, S extends Span<N, S>> {
		/**
		 * Check if this set has any spans
		 * 
		 * @return true if empty
		 */
		boolean isEmpty();

		/**
		 * Iterate the spans in this set
		 * 
		 * @return the iterable
		 */
		Iterable<S> spans();

		/**
		 * Get a span which encloses all spans in the set
		 * 
		 * @return the bounding span
		 */
		S bound();

		/**
		 * Check if the set contains the given value
		 * 
		 * @param n the value
		 * @return true if contained by any span in the set
		 */
		boolean contains(N n);

		/**
		 * Get the span containing the given value
		 * 
		 * @param n the value
		 * @return the span or null
		 */
		S spanContaining(N n);

		/**
		 * Iterate over all spans in the set that intersect the given span
		 * 
		 * @param s the span
		 * @return the iterable of spans
		 */
		Iterable<S> intersecting(S s);

		/**
		 * Iterate over the spans which are absent from the set but enclosed by the given span
		 * 
		 * @param s the span
		 * @return the iterable of spans
		 */
		default Iterable<S> complement(S s) {
			Domain<N, S> dom = s.domain();
			N min = s.min();
			List<S> result = new ArrayList<>();
			for (S i : intersecting(s)) {
				if (dom.compare(i.min(), min) > 0) {
					result.add(dom.closed(min, dom.dec(i.min())));
				}
				if (!i.maxIsFinite()) {
					return result;
				}
				min = dom.inc(i.max());
			}
			if (dom.compare(min, s.max()) <= 0) {
				result.add(dom.closed(min, s.max()));
			}
			return result;
		}

		/**
		 * Check if any span in the set intersects the given span
		 * 
		 * @param s the span
		 * @return true if any span in the set intersects it
		 */
		boolean intersects(S s);

		/**
		 * Check if any span in the set encloses the given span
		 * 
		 * @param s the span
		 * @return true if any span in the set encloses it
		 */
		default boolean encloses(S s) {
			S c = spanContaining(s.min());
			if (c == null) {
				return false;
			}
			return c.contains(s.max());
		}
	}

	/**
	 * An abstract interface for a mutable {@link SpanSet}
	 *
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 */
	public interface MutableSpanSet<N, S extends Span<N, S>> extends SpanSet<N, S> {
		/**
		 * Add a span to the set
		 * 
		 * <p>
		 * Any connected spans will be coalesced.
		 * 
		 * @param s the span
		 */
		void add(S s);

		/**
		 * Add all spans from the given set into this one
		 * 
		 * <p>
		 * The spans from both maps amy be coalesced when entered into this one. (The given map
		 * remains unmodified.)
		 * 
		 * @param set the other set
		 */
		void addAll(SpanSet<N, S> set);

		/**
		 * Remove a span from the set
		 * 
		 * <p>
		 * Spans which intersect the given span are truncated. Spans which are enclosed are deleted,
		 * such that no value in the given span remains in the set.
		 * 
		 * @param s the span
		 */
		void remove(S s);

		/**
		 * Remove all spans from the set
		 */
		void clear();
	}

	/**
	 * A partial implementation of {@link RangeMapSetter} for {@link Span}s.
	 *
	 * @param <E> the type of entries in the {@link SpanMap} implementation
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 * @param <V> the type of values
	 */
	abstract class SpanMapSetter<E, N, S extends Span<N, S>, V>
			extends RangeMapSetter<E, N, S, V> {

		/**
		 * Get the domain of the spans
		 * 
		 * @return the domain
		 */
		protected abstract Domain<N, S> domain();

		@Override
		protected int compare(N d1, N d2) {
			return domain().compare(d1, d2);
		}

		@Override
		protected N getLower(S range) {
			return range.min();
		}

		@Override
		protected N getUpper(S range) {
			return range.max();
		}

		@Override
		protected S toSpan(N lower, N upper) {
			return domain().closed(lower, upper);
		}

		@Override
		protected N getPrevious(N d) {
			if (domain().min().equals(d)) {
				return null;
			}
			return domain().dec(d);
		}

		@Override
		protected N getNext(N d) {
			if (domain().max().equals(d)) {
				return null;
			}
			return domain().inc(d);
		}
	}

	/**
	 * The default implementation of {@link SpanMap} and {@link MutableSpanMap} using an interval
	 * tree
	 *
	 * <p>
	 * The interfaces can prevent accidental mutation of a map where it shouldn't be allowed;
	 * however, nothing prevents a client from casting to the mutable interface. If proper
	 * immutability is required, this will need to be wrapped or extended to prevent mutation.
	 *
	 * @implNote While this map is concrete and can be used as is for spans in the given domain, it
	 *           is recommended to create your own extension implementing an interface specific to
	 *           your span type and domain.
	 *
	 * @param <N> the type of endpoints
	 * @param <S> the type of spans
	 * @param <V> the type of values
	 */
	public class DefaultSpanMap<N, S extends Span<N, S>, V> implements MutableSpanMap<N, S, V> {
		/**
		 * The setter, which handles coalescing and truncating entries
		 */
		private class Setter extends SpanMapSetter<Entry<N, Entry<S, V>>, N, S, V> {
			private final Domain<N, S> domain;

			/**
			 * Create a setter for the given domain
			 * 
			 * @param domain the domain
			 */
			public Setter(Domain<N, S> domain) {
				this.domain = domain;
			}

			@Override
			protected Domain<N, S> domain() {
				return domain;
			}

			@Override
			protected S getRange(Entry<N, Entry<S, V>> entry) {
				return entry.getValue().getKey();
			}

			@Override
			protected V getValue(Entry<N, Entry<S, V>> entry) {
				return entry.getValue().getValue();
			}

			@Override
			protected void remove(Entry<N, Entry<S, V>> entry) {
				spanTree.remove(entry.getKey());
			}

			@Override
			protected Iterable<Entry<N, Entry<S, V>>> getIntersecting(N lower, N upper) {
				return subMap(lower, upper).entrySet();
			}

			@Override
			protected Entry<N, Entry<S, V>> put(S range, V value) {
				if (value != null) {
					spanTree.put(range.min(), Map.entry(range, value));
				}
				return null;
			}
		}

		private final Domain<N, S> domain;
		private final DefaultSpanMap<N, S, V>.Setter setter;
		private final NavigableMap<N, Entry<S, V>> spanTree;

		/**
		 * Create a span map on the given domain
		 * 
		 * <p>
		 * Extensions should invoke this as a super constructor with a fixed domain. See
		 * {@link DefaultULongSpanMap} for an example.
		 * 
		 * @param domain the domain
		 */
		public DefaultSpanMap(Domain<N, S> domain) {
			this.domain = domain;
			this.setter = new Setter(domain);
			this.spanTree = new TreeMap<>(domain::compare);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof @SuppressWarnings("rawtypes") DefaultSpanMap that)) {
				return false;
			}
			if (this.domain != that.domain) {
				return false;
			}
			if (!Objects.equals(this.spanTree, that.spanTree)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return "{" + spanTree.values()
					.stream()
					.map(e -> domain.toString(e.getKey()) + '=' + e.getValue())
					.collect(Collectors.joining(",")) +
				"}";
		}

		@Override
		public boolean isEmpty() {
			return spanTree.isEmpty();
		}

		@Override
		public Set<S> spans() {
			// TODO: Make this a view?
			return spanTree.values().stream().map(e -> e.getKey()).collect(Collectors.toSet());
		}

		@Override
		public S bound() {
			if (spanTree.isEmpty()) {
				return domain.empty();
			}
			S first = spanTree.firstEntry().getValue().getKey();
			S last = spanTree.lastEntry().getValue().getKey();
			return first.bound(last);
		}

		@Override
		public Collection<V> values() {
			return spanTree.values().stream().map(e -> e.getValue()).collect(Collectors.toSet());
		}

		@Override
		public Set<Entry<S, V>> entries() {
			return Set.copyOf(spanTree.values());
		}

		@Override
		public Entry<S, V> getEntry(N n) {
			Entry<N, Entry<S, V>> floor = spanTree.floorEntry(n);
			if (floor == null) {
				return null;
			}
			Entry<S, V> ent = floor.getValue();
			if (!ent.getKey().contains(n)) {
				return null;
			}
			return ent;
		}

		@Override
		public V get(N n) {
			Entry<S, V> ent = getEntry(n);
			return ent == null ? null : ent.getValue();
		}

		/**
		 * Get the portion of the interval tree whose entries intersect the given span
		 * 
		 * @param min the lower endpoint of the span
		 * @param max the upper endpoint of the span
		 * @return the sub map
		 */
		protected NavigableMap<N, Entry<S, V>> subMap(N min, N max) {
			Entry<N, Entry<S, V>> adjEnt = spanTree.floorEntry(min);
			if (adjEnt != null && adjEnt.getValue().getKey().contains(min)) {
				min = adjEnt.getKey();
			}
			return spanTree.subMap(min, true, max, true);
		}

		@Override
		public Collection<Entry<S, V>> intersectingEntries(S s) {
			return subMap(s.min(), s.max()).values();
		}

		@Override
		public Iterable<S> intersectingSpans(S s) {
			return intersectingEntries(s).stream()
					.map(e -> e.getKey())
					.collect(Collectors.toList());
		}

		@Override
		public boolean intersects(S s) {
			Entry<N, Entry<S, V>> entry = spanTree.floorEntry(s.max());
			return entry != null && entry.getValue().getKey().intersects(s);
		}

		@Override
		public void put(S s, V v) {
			if (s.isEmpty()) {
				return;
			}
			setter.set(s, v);
		}

		@Override
		public void putAll(SpanMap<N, S, V> map) {
			for (Entry<S, V> entry : map.entries()) {
				put(entry.getKey(), entry.getValue());
			}
		}

		@Override
		public void remove(S s) {
			setter.set(s, null);
		}

		@Override
		public void clear() {
			spanTree.clear();
		}
	}

	/**
	 * The default implementation of {@link SpanSet} and {@link MutableSpanSet} using an interval
	 * tree
	 * 
	 * @param <N> the type of endpoints
	 * @param <S> the type of values
	 */
	public class DefaultSpanSet<N, S extends Span<N, S>> implements MutableSpanSet<N, S> {
		private final MutableSpanMap<N, S, Boolean> map;
		private final Domain<N, S> domain;

		/**
		 * Create a span set on the given domain
		 * 
		 * <p>
		 * Extensions should invoke this as a super constructor with a fixed domain. See
		 * {@link DefaultULongSpanSet} for an example.
		 * 
		 * @param domain the domain
		 */
		public DefaultSpanSet(Domain<N, S> domain) {
			this.map = newSpanMap(domain);
			this.domain = domain;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof @SuppressWarnings("rawtypes") DefaultSpanSet that)) {
				return false;
			}
			if (!Objects.equals(this.map, that.map)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return '[' +
				map.spans().stream().map(s -> domain.toString(s)).collect(Collectors.joining(",")) +
				']';
		}

		/**
		 * Factory method for the span map backing this span set
		 * 
		 * @param domain the domain
		 * @return the map
		 */
		protected MutableSpanMap<N, S, Boolean> newSpanMap(Domain<N, S> domain) {
			return new DefaultSpanMap<>(domain);
		}

		@Override
		public boolean isEmpty() {
			return map.isEmpty();
		}

		@Override
		public Iterable<S> spans() {
			return map.spans();
		}

		@Override
		public S bound() {
			return map.bound();
		}

		@Override
		public boolean contains(N n) {
			return Boolean.TRUE.equals(map.get(n));
		}

		@Override
		public S spanContaining(N n) {
			Entry<S, Boolean> entry = map.getEntry(n);
			return entry == null ? null : entry.getKey();
		}

		@Override
		public Iterable<S> intersecting(S s) {
			return map.intersectingSpans(s);
		}

		@Override
		public boolean intersects(S s) {
			return map.intersects(s);
		}

		@Override
		public void add(S s) {
			map.put(s, true);
		}

		@Override
		public void addAll(SpanSet<N, S> set) {
			// TODO: May not be the most efficient. A linear merge algorithm may do better....
			for (S s : set.spans()) {
				add(s);
			}
		}

		@Override
		public void remove(S s) {
			map.remove(s);
		}

		@Override
		public void clear() {
			map.clear();
		}
	}

	@SuppressWarnings("unchecked")
	default String doToString() {
		return domain().toString((S) this);
	}

	/**
	 * Get the domain of this span's endpoints
	 * 
	 * @implNote a span implementation should probably return a fixed singleton instance for its
	 *           domain.
	 * @return the domain
	 */
	Domain<N, S> domain();

	/**
	 * Get the lower enpdoint
	 * 
	 * @return the lower endpoint
	 * @throws NoSuchElementException if the span is empty
	 * @see #isEmpty()
	 */
	N min();

	/**
	 * Get the upper endpoint
	 * 
	 * @return the upper endpoint
	 * @throws NoSuchElementException if the span is empty
	 * @see #isEmpty()
	 */
	N max();

	/**
	 * Check if the lower endpoint excludes the domain minimum
	 * 
	 * @return true if min is not the domain min
	 */
	default boolean minIsFinite() {
		return !min().equals(domain().min());
	}

	/**
	 * Check if the upper endpoint excludes the domain maximum
	 * 
	 * @return true if max is not the domain max
	 */
	default boolean maxIsFinite() {
		return !max().equals(domain().max());
	}

	/**
	 * Check if this span is empty
	 * 
	 * @return true if empty
	 */
	default boolean isEmpty() {
		return false;
	}

	/**
	 * Check if this span contains the given value
	 * 
	 * @param n the value
	 * @return true if n is contained in this span
	 */
	default boolean contains(N n) {
		return domain().compare(min(), n) <= 0 && domain().compare(n, max()) <= 0;
	}

	/**
	 * Compute the intersection of this span and another
	 * 
	 * @param s another span
	 * @return the intersection, possibly empty
	 * @see Domain#intersect(Span, Span)
	 */
	@SuppressWarnings("unchecked")
	default S intersect(S s) {
		return domain().intersect((S) this, s);
	}

	/**
	 * Check if this span intersects a given span
	 * 
	 * @param s another span
	 * @return true if they intersect
	 * @see Domain#intersects(Span, Span)
	 */
	@SuppressWarnings("unchecked")
	default boolean intersects(S s) {
		return domain().intersects((S) this, s);
	}

	/**
	 * Check if this span encloses a given span
	 * 
	 * @param s another span
	 * @return true if this encloses the given span
	 */
	@SuppressWarnings("unchecked")
	default boolean encloses(S s) {
		return domain().encloses((S) this, s);
	}

	/**
	 * Compute the bound of this span and another
	 * 
	 * @param s another span
	 * @return the bound
	 * @see Domain#bound(Span, Span)
	 */
	@SuppressWarnings("unchecked")
	default S bound(S s) {
		return domain().bound((S) this, s);
	}

	/**
	 * Subtract a span from this span
	 * 
	 * @param s the span to subtract
	 * @return 0, 1, or 2 spans resulting from the subtraction
	 */
	@SuppressWarnings("unchecked")
	default List<S> subtract(S s) {
		return domain().subtract((S) this, s);
	}

	@Override
	default int compareTo(S that) {
		if (this.isEmpty()) {
			if (that.isEmpty()) {
				return 0;
			}
			return -1;
		}
		if (that.isEmpty()) {
			return 1;
		}
		int result;
		result = domain().compare(this.min(), that.min());
		if (result != 0) {
			return result;
		}
		result = domain().compare(this.max(), that.max());
		if (result != 0) {
			return result;
		}
		return 0;
	}
}
