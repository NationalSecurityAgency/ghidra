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

import db.Field;
import generic.End;
import generic.End.*;
import generic.Span;
import ghidra.util.database.DirectedIterator.Direction;

/**
 * A span of database field values
 * 
 * <p>
 * We must allow open endpoints here. Consider a string field. There is no well-defined increment or
 * decrement on strings. Let them be ordered lexicographically. What string <em>immediately</em>
 * precedes {@code "Span"}? It is not {@code "Spam"}, since {@code "Spammer"} falls between. In
 * fact, for any string having the prefix {@code "Spam"}, you can add another character to it to
 * find a string after it, but still preceding {@code "Span"}. Thus, we use {@link EndSpan}, so that
 * {@code End("Span" - epsilon)} can stand in for the value immediately preceding {@code "Span"}.
 */
public sealed interface FieldSpan extends EndSpan<Field, FieldSpan> {
	FieldSpan.Domain DOMAIN = new FieldSpan.Domain();
	FieldSpan.Empty EMPTY = Empty.INSTANCE;
	FieldSpan.Impl ALL = new Impl(DOMAIN.min(), DOMAIN.max());

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
	static FieldSpan sub(Field from, boolean fromInclusive, Field to, boolean toInclusive,
			Direction direction) {
		if (from.equals(to) && (!fromInclusive || !toInclusive)) {
			return EMPTY;
		}
		return direction == Direction.FORWARD
				? DOMAIN.closed(End.lower(from, fromInclusive), End.upper(to, toInclusive))
				: DOMAIN.closed(End.lower(to, toInclusive), End.upper(from, fromInclusive));
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
	static FieldSpan head(Field to, boolean toInclusive, Direction direction) {
		return direction == Direction.FORWARD
				? DOMAIN.closed(End.negativeInfinity(), End.upper(to, toInclusive))
				: DOMAIN.closed(End.lower(to, toInclusive), End.positiveInfinity());
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
	static FieldSpan tail(Field from, boolean fromInclusive, Direction direction) {
		return direction == Direction.FORWARD
				? DOMAIN.closed(End.lower(from, fromInclusive), End.positiveInfinity())
				: DOMAIN.closed(End.negativeInfinity(), End.upper(from, fromInclusive));
	}

	/**
	 * The domain of field values, allowing open endpoints
	 */
	public class Domain extends EndDomain<Field, FieldSpan> {
		private Domain() {
			super(Field::compareTo);
		}

		@Override
		public FieldSpan closed(End<Field> min, End<Field> max) {
			if (!min.isValidMin()) {
				throw new IllegalArgumentException("Invalid min: " + min);
			}
			if (!max.isValidMax()) {
				throw new IllegalArgumentException("Invalid max: " + max);
			}
			return super.closed(min, max);
		}

		@Override
		public FieldSpan newSpan(End<Field> min, End<Field> max) {
			return new Impl(min, max);
		}

		@Override
		public FieldSpan empty() {
			return EMPTY;
		}

		@Override
		public FieldSpan all() {
			return ALL;
		}
	}

	/**
	 * The singleton empty span of field values
	 */
	final class Empty implements FieldSpan, Span.Empty<End<Field>, FieldSpan> {
		private static final FieldSpan.Empty INSTANCE = new FieldSpan.Empty();

		private Empty() {
		}

		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public Span.Domain<End<Field>, FieldSpan> domain() {
			return DOMAIN;
		}
	}

	/**
	 * A span of field values
	 */
	record Impl(End<Field> min, End<Field> max) implements FieldSpan {
		@Override
		public String toString() {
			return doToString();
		}

		@Override
		public Span.Domain<End<Field>, FieldSpan> domain() {
			return DOMAIN;
		}
	}
}
