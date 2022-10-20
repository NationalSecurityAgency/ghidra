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

/**
 * A span of unsigned longs
 * 
 * <p>
 * While the type of endpoint is {@link Long}, the domain imposes unsigned behavior. To ensure
 * consistent behavior in client code, comparisons and manipulations should be performed via
 * {@link #DOMAIN}, where applicable.
 */
public interface ULongSpan extends Span<Long, ULongSpan> {
	ULongSpan.Domain DOMAIN = ULongSpan.Domain.INSTANCE;
	ULongSpan.Empty EMPTY = Empty.INSTANCE;
	ULongSpan.Impl ALL = new Impl(DOMAIN.min(), DOMAIN.max());

	/**
	 * Create a closed interval of unsigned longs
	 * 
	 * @param min the lower bound
	 * @param max the upper bound
	 * @return the span
	 * @throws IllegalArgumentException if {@code max < min}
	 */
	public static ULongSpan span(long min, long max) {
		return DOMAIN.closed(min, max);
	}

	/**
	 * Create a closed interval of unsigned longs having a given length
	 * 
	 * @param min the lower bound
	 * @param length the length
	 * @return the span
	 * @throws IllegalArgumentException if the upper endpoint would exceed {@link Domain#max()}
	 */
	public static ULongSpan extent(long min, long length) {
		return DOMAIN.closed(min, min + length - 1);
	}

	/**
	 * Create a closed interval of unsigned longs having the given (unsigned) length
	 * 
	 * <p>
	 * This operates the same as {@link #extent(long, int)}, but ensures the given length is treated
	 * as an unsigned integer.
	 * 
	 * @param min
	 * @param length
	 * @return the span
	 * @throws IllegalArgumentException if the upper endpoint would exceed {@link Domain#max()}
	 */
	public static ULongSpan extent(long min, int length) {
		return extent(min, Integer.toUnsignedLong(length));
	}

	/**
	 * The domain of unsigned longs
	 */
	public enum Domain implements Span.Domain<Long, ULongSpan> {
		INSTANCE;

		@Override
		public ULongSpan newSpan(Long min, Long max) {
			return new Impl(min, max);
		}

		@Override
		public ULongSpan all() {
			return ALL;
		}

		@Override
		public ULongSpan empty() {
			return EMPTY;
		}

		@Override
		public String toString(Long n) {
			return Long.toUnsignedString(n);
		}

		@Override
		public int compare(Long n1, Long n2) {
			return Long.compareUnsigned(n1, n2);
		}

		@Override
		public Long min() {
			return 0L;
		}

		@Override
		public Long max() {
			return -1L;
		}

		@Override
		public Long inc(Long n) {
			return n + 1;
		}

		@Override
		public Long dec(Long n) {
			return n - 1;
		}
	}

	/**
	 * The singleton empty span of unsigned longs
	 */
	class Empty implements ULongSpan, Span.Empty<Long, ULongSpan> {
		private static final ULongSpan.Empty INSTANCE = new ULongSpan.Empty();

		private Empty() {
		}

		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public ULongSpan.Domain domain() {
			return DOMAIN;
		}

		@Override
		public long length() {
			return 0;
		}
	}

	/**
	 * A non-empty span of unsigned longs
	 */
	record Impl(Long min, Long max) implements ULongSpan {
		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public Span.Domain<Long, ULongSpan> domain() {
			return DOMAIN;
		}
	}

	/**
	 * A map of unsigned long spans to values
	 * 
	 * @param <V> the type of values
	 */
	interface ULongSpanMap<V> extends SpanMap<Long, ULongSpan, V> {
	}

	/**
	 * A mutable map of unsigned long spans to values
	 * 
	 * @param <V> the type of values
	 */
	interface MutableULongSpanMap<V> extends ULongSpanMap<V>, MutableSpanMap<Long, ULongSpan, V> {
	}

	/**
	 * An interval tree implementing {@link MutableULongSpanMap}
	 *
	 * @param <V> the type of values
	 */
	class DefaultULongSpanMap<V> extends DefaultSpanMap<Long, ULongSpan, V>
			implements MutableULongSpanMap<V> {
		public DefaultULongSpanMap() {
			super(DOMAIN);
		}
	}

	/**
	 * A set of unsigned long spans
	 */
	interface ULongSpanSet extends SpanSet<Long, ULongSpan> {
		static ULongSpanSet of(ULongSpan... spans) {
			MutableULongSpanSet result = new DefaultULongSpanSet();
			for (ULongSpan s : spans) {
				result.add(s);
			}
			return result;
		}
	}

	/**
	 * A mutable set of unsigned long spans
	 */
	interface MutableULongSpanSet extends ULongSpanSet, MutableSpanSet<Long, ULongSpan> {
	}

	/**
	 * An interval tree implementing {@link MutableULongSpanSet}
	 */
	class DefaultULongSpanSet extends DefaultSpanSet<Long, ULongSpan>
			implements MutableULongSpanSet {
		public DefaultULongSpanSet() {
			super(DOMAIN);
		}
	}

	/**
	 * Get the length of the span
	 * 
	 * @return the length
	 */
	default long length() {
		return max() - min() + 1;
	}
}
