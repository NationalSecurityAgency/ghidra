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

import java.io.IOException;

import com.google.common.collect.BoundType;
import com.google.common.collect.Range;

import db.Table;

/**
 * An iterator over some component of a {@link Table}
 * 
 * @param <T> the type of the component, i.e., a key or record
 */
public interface DirectedIterator<T> {
	/**
	 * The direction of iteration
	 */
	public enum Direction {
		FORWARD {
			@Override
			Direction reverse() {
				return BACKWARD;
			}
		},
		BACKWARD {
			@Override
			Direction reverse() {
				return FORWARD;
			}
		};

		/**
		 * Get the reverse of this direction
		 * 
		 * @return the reverse
		 */
		abstract Direction reverse();

		/**
		 * Get the reverse of the given direction
		 * 
		 * @param direction the direction
		 * @return the reverse
		 */
		static Direction reverse(Direction direction) {
			return direction.reverse();
		}
	}

	/**
	 * Get the discrete lower bound of the given range
	 * 
	 * @param range the range
	 * @return the lower bound
	 */
	static long toIteratorMin(Range<Long> range) {
		if (range == null) {
			return Long.MIN_VALUE;
		}
		else if (!range.hasLowerBound()) {
			return Long.MIN_VALUE;
		}
		else if (range.lowerBoundType() == BoundType.CLOSED) {
			return range.lowerEndpoint();
		}
		else {
			return range.lowerEndpoint() + 1;
		}
	}

	/**
	 * Get the discrete upper bound of the given range
	 * 
	 * @param range the range
	 * @return the upper bound
	 */
	static long toIteratorMax(Range<Long> range) {
		if (range == null) {
			return Long.MAX_VALUE;
		}
		else if (!range.hasUpperBound()) {
			return Long.MAX_VALUE;
		}
		else if (range.upperBoundType() == BoundType.CLOSED) {
			return range.upperEndpoint();
		}
		else {
			return range.upperEndpoint() - 1;
		}
	}

	/**
	 * Compute the effective starting point for a forward iterator starting at the given bound
	 * 
	 * @param range the range describing a limited view of keys
	 * @param bound the starting key
	 * @param inclusive whether the starting key is included
	 * @return the starting point, inclusive
	 */
	static long clampLowerBound(Range<Long> range, long bound, boolean inclusive) {
		return Math.max(toIteratorMin(range), inclusive ? bound : bound + 1);
	}

	/**
	 * Compute the effective starting point for a backward iterator starting at the given bound
	 * 
	 * @param range the range describing a limited view of keys
	 * @param bound the starting key
	 * @param inclusive whether the starting key is included
	 * @return the starting point, inclusive
	 */
	static long clampUpperBound(Range<Long> range, long bound, boolean inclusive) {
		return Math.min(toIteratorMax(range), inclusive ? bound : bound - 1);
	}

	/**
	 * Check if the table has another record
	 * 
	 * @return true if so
	 * @throws IOException if the table cannot be read
	 */
	boolean hasNext() throws IOException;

	/**
	 * Get the component of the next record
	 * 
	 * @return the component
	 * @throws IOException if the table cannot be read
	 */
	T next() throws IOException;

	/**
	 * Delete the current record
	 * 
	 * @return true if successful
	 * @throws IOException if the table cannot be accessed
	 */
	boolean delete() throws IOException;
}
