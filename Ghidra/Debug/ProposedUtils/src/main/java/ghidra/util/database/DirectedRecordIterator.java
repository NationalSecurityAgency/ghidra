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

import db.*;

public interface DirectedRecordIterator extends DirectedIterator<DBRecord> {

	public static AbstractDirectedRecordIterator getIterator(Table table, Range<Long> keyRange,
			Direction direction) throws IOException {
		long min = DirectedIterator.toIteratorMin(keyRange);
		long max = DirectedIterator.toIteratorMax(keyRange);
		if (direction == Direction.FORWARD) {
			return new ForwardRecordIterator(table.iterator(min, max, min));
		}
		return new BackwardRecordIterator(table.iterator(min, max, max));
	}

	private static DirectedRecordIterator applyBegFilter(DirectedRecordIterator it, int columnIndex,
			Field exclude) throws IOException {
		return new DirectedRecordIterator() {
			DBRecord next = findFirst();

			private DBRecord findFirst() throws IOException {
				DBRecord r = null;
				while (it.hasNext()) {
					r = it.next();
					if (r.getFieldValue(columnIndex).equals(exclude)) {
						continue;
					}
					return r;
				}
				return null;
			}

			@Override
			public DBRecord next() throws IOException {
				DBRecord ret = next;
				next = it.next();
				return ret;
			}

			@Override
			public boolean hasNext() throws IOException {
				return next != null;
			}

			@Override
			public boolean delete() throws IOException {
				// TODO
				throw new UnsupportedOperationException();
			}
		};
	}

	private static DirectedRecordIterator applyEndFilter(DirectedRecordIterator it, int columnIndex,
			Field exclude) throws IOException {
		return new DirectedRecordIterator() {
			DBRecord next = it.next();

			@Override
			public DBRecord next() throws IOException {
				DBRecord ret = next;
				next = it.next();
				return ret;
			}

			@Override
			public boolean hasNext() throws IOException {
				return next != null && !next.getFieldValue(columnIndex).equals(exclude);
			}

			@Override
			public boolean delete() throws IOException {
				// TODO
				throw new UnsupportedOperationException();
			}
		};
	}

	private static DirectedRecordIterator applyFilters(DirectedRecordIterator it, int columnIndex,
			Field beg, Field end) throws IOException {
		// TODO: Just use Apache's FilteringIterator for both of these. It supports delete.
		if (beg != null) {
			it = applyBegFilter(it, columnIndex, beg);
		}
		if (end != null) {
			it = applyEndFilter(it, columnIndex, end);
		}
		return it;
	}

	public static DirectedRecordIterator getIndexIterator(Table table, int columnIndex,
			Range<Field> fieldRange, Direction direction) throws IOException {
		Field lower = fieldRange.hasLowerBound() ? fieldRange.lowerEndpoint() : null;
		Field upper = fieldRange.hasUpperBound() ? fieldRange.upperEndpoint() : null;
		RecordIterator it =
			table.indexIterator(columnIndex, lower, upper, direction == Direction.FORWARD);
		Field excludeLower =
			fieldRange.hasLowerBound() && fieldRange.lowerBoundType() == BoundType.OPEN ? lower
					: null;
		Field excludeUpper =
			fieldRange.hasUpperBound() && fieldRange.upperBoundType() == BoundType.OPEN ? upper
					: null;
		if (direction == Direction.FORWARD) {
			return applyFilters(new ForwardRecordIterator(it), columnIndex, excludeLower,
				excludeUpper);
		}
		return applyFilters(new BackwardRecordIterator(it), columnIndex, excludeUpper,
			excludeLower);
	}
}
