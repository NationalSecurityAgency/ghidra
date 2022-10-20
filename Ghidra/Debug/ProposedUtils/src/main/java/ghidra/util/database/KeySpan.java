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
package ghidra.util.database;

import generic.Span;
import ghidra.util.database.DirectedIterator.Direction;

/**
 * An interval of database (primary) keys
 */
public sealed interface KeySpan extends Span<Long, KeySpan> {
	KeySpan.Domain DOMAIN = new KeySpan.Domain();
	KeySpan.Empty EMPTY = Empty.INSTANCE;
	KeySpan.Impl ALL = new Impl(DOMAIN.min(), DOMAIN.max());

	/**
	 * Get the span for a sub collection
	 * 
	 * <p>
	 * {@code from} must precede {@code to}, unless direction is {@link Direction#BACKWARD}, in
	 * which case the opposite is required. The endpoints may be equal but unless both are
	 * inclusive, the result is {@link #EMPTY}. The two endpoints are not automatically inverted to
	 * correct ordering. More often than not, accidental mis-ordering indicates an implementation
	 * flaw.
	 * 
	 * @param from the lower bound
	 * @param fromInclusive true if the bound includes {@code from}
	 * @param to the upper bound
	 * @param toInclusive true if the bound includes {@code to}
	 * @param direction the direction, true to swap {@code from} and {@code to}
	 * @return the span
	 */
	static KeySpan sub(long from, boolean fromInclusive, long to, boolean toInclusive,
			Direction direction) {
		if (from == to && (!fromInclusive || !toInclusive)) {
			return EMPTY;
		}
		return direction == Direction.FORWARD
				? DOMAIN.closed(fromInclusive ? from : from + 1, toInclusive ? to : to - 1)
				: DOMAIN.closed(toInclusive ? to : to + 1, fromInclusive ? from : from - 1);
	}

	/**
	 * Get the span for the head of a collection
	 * 
	 * <p>
	 * When {@code direction} is {@link Direction#BACKWARD} this behaves as if a tail collection;
	 * however, the implication is that iteration will start from the maximum and proceed toward the
	 * given bound.
	 * 
	 * @param to the upper bound
	 * @param toInclusive true if the bound includes {@code to}
	 * @param direction the direction, true to create a tail instead
	 * @return the span
	 */
	static KeySpan head(long to, boolean toInclusive, Direction direction) {
		if (to == DOMAIN.min() && !toInclusive) {
			return EMPTY;
		}
		return direction == Direction.FORWARD
				? DOMAIN.closed(DOMAIN.min(), toInclusive ? to : to - 1)
				: DOMAIN.closed(toInclusive ? to : to + 1, DOMAIN.max());
	}

	/**
	 * Get the span for the tail of a collection
	 * 
	 * <p>
	 * When {@code direction} is {@link Direction#BACKWARD} this behaves as if a head collection;
	 * however, the implication is that iteration will start from the bound and proceed toward the
	 * minimum.
	 * 
	 * @param from the lower bound
	 * @param fromInclusive true if the bound includes {@code to}
	 * @param direction the direction, true to create a head instead
	 * @return the span
	 */
	static KeySpan tail(long from, boolean fromInclusive, Direction direction) {
		if (from == DOMAIN.max() && !fromInclusive) {
			return EMPTY;
		}
		return direction == Direction.FORWARD
				? DOMAIN.closed(fromInclusive ? from : from + 1, DOMAIN.max())
				: DOMAIN.closed(DOMAIN.min(), fromInclusive ? from : from - 1);
	}

	/**
	 * Get the span for a closed interval
	 * 
	 * @implNote this is used primarily in testing
	 * @param from the lower endpoint
	 * @param to the upper endpoint
	 * @return the interval
	 */
	static KeySpan closed(long from, long to) {
		return DOMAIN.closed(from, to);
	}

	/**
	 * The domain of keys
	 */
	public class Domain implements Span.Domain<Long, KeySpan> {
		@Override
		public KeySpan newSpan(Long min, Long max) {
			return new Impl(min, max);
		}

		@Override
		public KeySpan empty() {
			return EMPTY;
		}

		@Override
		public KeySpan all() {
			return ALL;
		}

		@Override
		public int compare(Long n1, Long n2) {
			return Long.compare(n1, n2);
		}

		@Override
		public Long min() {
			return Long.MIN_VALUE;
		}

		@Override
		public Long max() {
			return Long.MAX_VALUE;
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
	 * The singleton empty span of keys
	 */
	final class Empty implements KeySpan, Span.Empty<Long, KeySpan> {
		private static final KeySpan.Empty INSTANCE = new KeySpan.Empty();

		private Empty() {
		}

		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public Span.Domain<Long, KeySpan> domain() {
			return DOMAIN;
		}
	}

	/**
	 * A non-empty span of keys
	 */
	record Impl(Long min, Long max) implements KeySpan {
		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public Span.Domain<Long, KeySpan> domain() {
			return DOMAIN;
		}
	}
}
