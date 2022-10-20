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

import db.*;
import generic.End.Point;

/**
 * An iterator over records of a table
 */
public interface DirectedRecordIterator extends DirectedIterator<DBRecord> {
	public final static DirectedRecordIterator EMPTY =
		new AbstractDirectedRecordIterator(null) {
			@Override
			public boolean hasNext() throws IOException {
				return false;
			}

			@Override
			public DBRecord next() throws IOException {
				return null;
			}
		};

	/**
	 * Get an iterator over the table, restricted to the given range of keys, in the given direction
	 * 
	 * @param table the table
	 * @param keySpan the limited range
	 * @param direction the direction
	 * @return the iterator
	 * @throws IOException if the table cannot be read
	 */
	public static DirectedRecordIterator getIterator(Table table, KeySpan keySpan,
			Direction direction) throws IOException {
		if (keySpan.isEmpty()) {
			return EMPTY;
		}
		long min = keySpan.min();
		long max = keySpan.max();
		if (direction == Direction.FORWARD) {
			return new ForwardRecordIterator(table.iterator(min, max, min));
		}
		return new BackwardRecordIterator(table.iterator(min, max, max));
	}

	/**
	 * Given an iterator over a closed range. Change its behavior to exclude the lower bound
	 * 
	 * @param it the iterator over the closed range
	 * @param columnIndex the column number whose index being iterated
	 * @param exclude the lower bound to be excluded
	 */
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

	/**
	 * Given an iterator over a closed range. Change its behavior to exclude the upper bound
	 * 
	 * @param it the iterator over the closed range
	 * @param columnIndex the column number whose index being iterated
	 * @param exclude the upper bound to be excluded
	 */
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

	/**
	 * Get an iterator over the table using a given index, restricted to the given range of values,
	 * in the given direction
	 * 
	 * @param table the table
	 * @param columnIndex the column number of the index
	 * @param fieldSpan the limited range
	 * @param direction the direction
	 * @return the iterator
	 * @throws IOException if the table cannot be read
	 */
	public static DirectedRecordIterator getIndexIterator(Table table, int columnIndex,
			FieldSpan fieldSpan, Direction direction) throws IOException {
		Field lower = fieldSpan.min() instanceof Point<Field> pt ? pt.val() : null;
		Field upper = fieldSpan.max() instanceof Point<Field> pt ? pt.val() : null;

		RecordIterator it =
			table.indexIterator(columnIndex, lower, upper, direction == Direction.FORWARD);
		Field excludeLower = !fieldSpan.min().isInclusive() ? lower : null;
		Field excludeUpper = !fieldSpan.max().isInclusive() ? upper : null;
		if (direction == Direction.FORWARD) {
			return applyFilters(new ForwardRecordIterator(it), columnIndex, excludeLower,
				excludeUpper);
		}
		return applyFilters(new BackwardRecordIterator(it), columnIndex, excludeUpper,
			excludeLower);
	}
}
