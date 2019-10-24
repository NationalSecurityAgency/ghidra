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
package docking.widgets.table.sort;

import java.util.Comparator;

/**
 * An interface that is conceptually the same as a {@link Comparator}.  The only difference is 
 * that we pass the row objects <b>and</b> the column values to 
 * {@link #compare(Object, Object, Object, Object)}.  This allows us to take advantage of 
 * already-retrieved column values.  This can speed-up table sorting, as repeatedly retrieving
 * column values for each comparison is slow.
 *
 * @param <T> the row type
 */
public interface BackupColumnComparator<T> {

	static final BackupColumnComparator<Object> NO_SORT_COMPARATOR = (t1, t2, o1, o2) -> 0;

	@SuppressWarnings("unchecked") // we are casting to Object; safe since no comparisons are done
	public static <T> BackupColumnComparator<T> getNoSortComparator() {
		return (BackupColumnComparator<T>) NO_SORT_COMPARATOR;
	}

	/**
	 * Compares two row/column values using the same contract as 
	 * {@link Comparator#compare(Object, Object)}
	 * 
	 * @param t1 the 1st row object
	 * @param t2 the 2nd row object
	 * @param c1 the 1st column value
	 * @param c2 the second column value
	 * @return 0 if the 2 values compare the same; negative if the first value compares less than
	 *         the second; positive if the first value compares as larger than the first
	 */
	public int compare(T t1, T t2, Object c1, Object c2);
}
