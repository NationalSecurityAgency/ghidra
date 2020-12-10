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

public interface DirectedIterator<T> {
	public enum Direction {
		FORWARD, BACKWARD;

		static Direction reverse(Direction direction) {
			if (direction == FORWARD) {
				return BACKWARD;
			}
			return FORWARD;
		}
	}

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

	static long clampLowerBound(Range<Long> range, long bound, boolean inclusive) {
		return Math.max(toIteratorMin(range), inclusive ? bound : bound + 1);
	}

	static long clampUpperBound(Range<Long> range, long bound, boolean inclusive) {
		return Math.min(toIteratorMax(range), inclusive ? bound : bound - 1);
	}

	boolean hasNext() throws IOException;

	T next() throws IOException;

	boolean delete() throws IOException;
}
