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

import java.util.Comparator;

import generic.Span.Domain;

/**
 * An endpoint for spans for specifying open endpoints
 *
 * <p>
 * This is achieved by considering a value +/- an optional epsilon, where epsilon is "the smallest
 * non-zero value". Closed endpoints do not have an epsilon. Open endpoint have an epsilon added or
 * subtracted, depending on whether it is a lower or upper endpoint, respectively. For example, the
 * interval (2, +inf) has the lower endpoint {@code 2 + epsilon} so that 2 is excluded, but any
 * number greater than 2 is included. There are some wrinkles, since the domain for values
 * necessitating open intervals is no longer discreet, but we can abuse {@link #dec()} and
 * {@link #inc()} to compute endpoints of connected intervals. We cannot allow negative epsilon to
 * be used on lower bounds and vice versa, though. This is a natural restriction, because such
 * intervals wouldn't make sense, but it also overcomes the situation where {@link #dec()} or
 * {@link #inc()} would need to change the value. Instead, they need only adjust the use of epsilon.
 *
 * @param <T> the type of values
 */
public interface End<T> {
	/**
	 * Get the endpoint representing no lower bound
	 * 
	 * <p>
	 * This always returns the same instance of negative infinity. Clients can rely on identity when
	 * checking for equality.
	 * 
	 * @param <T> the type of values
	 * @return negative "infinity"
	 */
	@SuppressWarnings("unchecked")
	static <T> End<T> negativeInfinity() {
		return (End<T>) Unbound.NEG_INF;
	}

	/**
	 * Get the endpoint representing no upper bound
	 * 
	 * <p>
	 * This always returns the same instance of positive infinity. Clients can rely on identity when
	 * checking for equality.
	 * 
	 * @param <T> the type of values
	 * @return positive "infinity"
	 */
	@SuppressWarnings("unchecked")
	static <T> End<T> positiveInfinity() {
		return (End<T>) Unbound.POS_INF;
	}

	/**
	 * Construct a lower endpoint
	 * 
	 * @param <T> the type of value
	 * @param value the value
	 * @param inclusive whether the endpoint includes the given value
	 * @return the endpoint
	 */
	static <T> End<T> lower(T value, boolean inclusive) {
		return new Point<>(value, inclusive ? Epsilon.ZERO : Epsilon.POSITIVE);
	}

	/**
	 * Construct an upper endpoint
	 * 
	 * @param <T> the type of value
	 * @param value the value
	 * @param inclusive whether the endpoint includes the given value
	 * @return the endpoint
	 */
	static <T> End<T> upper(T value, boolean inclusive) {
		return new Point<>(value, inclusive ? Epsilon.ZERO : Epsilon.NEGATIVE);
	}

	/**
	 * An enum for the two values of infinity
	 */
	enum Unbound implements End<Void> {
		NEG_INF {
			@Override
			public int compareTo(End<Void> that, Comparator<Void> comparator) {
				return that == NEG_INF ? 0 : -1;
			}

			@Override
			public End<Void> dec() {
				return NEG_INF;
			}

			@Override
			public String toMinString() {
				return "(-inf";
			}

			@Override
			public String toMaxString() {
				return "#ERROR-inf)";
			}

			@Override
			public boolean isValidMin() {
				return true;
			}

			@Override
			public boolean isValidMax() {
				return false;
			}
		},
		POS_INF {
			@Override
			public int compareTo(End<Void> that, Comparator<Void> comparator) {
				return that == POS_INF ? 0 : 1;
			}

			@Override
			public End<Void> inc() {
				return POS_INF;
			}

			@Override
			public String toMinString() {
				return "(#ERROR+inf";
			}

			@Override
			public String toMaxString() {
				return "+inf)";
			}

			@Override
			public boolean isValidMin() {
				return false;
			}

			@Override
			public boolean isValidMax() {
				return true;
			}
		};

		@Override
		public End<Void> inc() {
			throw new UnsupportedOperationException();
		}

		@Override
		public End<Void> dec() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isInclusive() {
			return false;
		}
	}

	/**
	 * An enum for the three allowed coefficients of epsilon
	 */
	enum Epsilon {
		/** {@code value - 1*epsilon}, -1 for open upper endpoints */
		NEGATIVE {
			@Override
			Epsilon inc() {
				return ZERO;
			}

			@Override
			Epsilon dec() {
				throw new UnsupportedOperationException();
			}
		},
		/** {@code value + 0*epsilon}, 0 for closed enpoints */
		ZERO {
			@Override
			Epsilon inc() {
				return POSITIVE;
			}

			@Override
			Epsilon dec() {
				return NEGATIVE;
			}
		},
		/** {@code value + epsilon}, 1 for open lower endpoints */
		POSITIVE {
			@Override
			Epsilon inc() {
				throw new UnsupportedOperationException();
			}

			@Override
			Epsilon dec() {
				return ZERO;
			}
		};

		/**
		 * Compute the epsilon for an incremented endpoint
		 * 
		 * @return the new "incremented" epsilon
		 * @throws UnsupportedOperationException if this is already {@link #POSITIVE}
		 */
		abstract Epsilon inc();

		/**
		 * Compute the epsilon for a decremented endpoint
		 * 
		 * @return the new "decremented" epsilon
		 * @throws UnsupportedOperationException if this is already {@link #NEGATIVE}
		 */
		abstract Epsilon dec();
	}

	/**
	 * An endpoint representing a bound
	 *
	 * @param <T> the type of values
	 */
	record Point<T> (T val, Epsilon epsilon) implements End<T> {
		@Override
		public String toMinString() {
			switch (epsilon) {
				case NEGATIVE:
					return "(#ERROR" + val;
				case ZERO:
					return "[" + val;
				case POSITIVE:
					return "(" + val;
			}
			throw new AssertionError();
		}

		@Override
		public String toMaxString() {
			switch (epsilon) {
				case NEGATIVE:
					return val + ")";
				case ZERO:
					return val + "]";
				case POSITIVE:
					return "#ERROR" + val + ")";
			}
			throw new AssertionError();
		}

		@Override
		public End<T> inc() {
			return new Point<>(val, epsilon.inc());
		}

		@Override
		public End<T> dec() {
			return new Point<>(val, epsilon.dec());
		}

		@Override
		public boolean isValidMin() {
			return epsilon != Epsilon.NEGATIVE;
		}

		@Override
		public boolean isValidMax() {
			return epsilon != Epsilon.POSITIVE;
		}

		@Override
		public boolean isInclusive() {
			return epsilon == Epsilon.ZERO;
		}

		@Override
		public int compareTo(End<T> that, Comparator<T> comparator) {
			if (that == Unbound.NEG_INF) {
				return 1;
			}
			if (that == Unbound.POS_INF) {
				return -1;
			}
			if (that instanceof Point<T> point) {
				int result = comparator.compare(this.val, point.val);
				if (result != 0) {
					return result;
				}
				result = this.epsilon.compareTo(point.epsilon);
				if (result != 0) {
					return result;
				}
				return 0;
			}
			throw new AssertionError();
		}
	}

	/**
	 * An interface of intervals with open, closed, or unbounded endpoints
	 *
	 * @param <N> the type of values
	 * @param <S> the type of spans
	 */
	public interface EndSpan<N, S extends EndSpan<N, S>> extends Span<End<N>, S> {
		/**
		 * Check if this interval contains the given value
		 * 
		 * <p>
		 * This is equivalent to, and a shortcut for, {@link #contains(Object)}, passing
		 * {@code value + 0*epsilon}.
		 * 
		 * @param n the value
		 * @return true if contained
		 */
		default boolean containsPoint(N n) {
			return contains(new Point<>(n, Epsilon.ZERO));
		}
	}

	/**
	 * The domain for spans of {@link End}
	 * 
	 * <p>
	 * Because the domain is no longer necessarily discreet, only comparison is necessary to
	 * implement it. {@link #dec(End)} and {@link #inc(End)} are instead applied to the coefficient
	 * on epsilon to find connected intervals.
	 * 
	 * @param <N> the type of values
	 * @param <S> the type of spans
	 */
	public abstract class EndDomain<N, S extends EndSpan<N, S>> implements Span.Domain<End<N>, S> {
		private final Comparator<N> comparator;

		/**
		 * Construct a domain using the given comparator
		 * 
		 * @param comparator the comparator for values
		 */
		public EndDomain(Comparator<N> comparator) {
			this.comparator = comparator;
		}

		@Override
		public String toMinString(End<N> min) {
			return min.toMinString();
		}

		@Override
		public String toMaxString(End<N> max) {
			return max.toMaxString();
		}

		@Override
		public int compare(End<N> n1, End<N> n2) {
			return n1.compareTo(n2, comparator);
		}

		@Override
		public End<N> min() {
			return negativeInfinity();
		}

		@Override
		public End<N> max() {
			return positiveInfinity();
		}

		@Override
		public End<N> inc(End<N> n) {
			return n.inc();
		}

		@Override
		public End<N> dec(End<N> n) {
			return n.dec();
		}
	}

	/**
	 * @see Domain#toMinString(Object)
	 * @return the string
	 */
	String toMinString();

	/**
	 * @see Domain#toMaxString(Object)
	 * @return the string
	 */
	String toMaxString();

	/**
	 * Increment this endpoint, only by changing the coefficient of epsilon
	 * 
	 * @return the resulting endpoint
	 */
	End<T> inc();

	/**
	 * Decrement this endpoint, only by changing the coefficient of epsilon
	 * 
	 * @return the resulting endpoint
	 */
	End<T> dec();

	/**
	 * Compare two endpoints
	 * 
	 * <p>
	 * First, the values of infinity are considered. Then, the values of the endpoints are
	 * considered. Finally, the coefficients of epsilon are considered.
	 * 
	 * @param that the other endpoint
	 * @param comparator the value comparator
	 * @return the result as in {@link Comparator#compare(Object, Object)}
	 */
	int compareTo(End<T> that, Comparator<T> comparator);

	/**
	 * Check if this endpoint is allowed as a lower endpoint
	 * 
	 * @return true if allowed
	 */
	boolean isValidMin();

	/**
	 * Check if this endpoint is allowed as an upper endpoint
	 * 
	 * @return true if allowed
	 */
	boolean isValidMax();

	/**
	 * Check if this endpoint includes its value
	 * 
	 * @return true if included
	 */
	boolean isInclusive();
}
