/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.datastruct;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.*;

/**
 * <CODE>Algorithms</CODE> is a class containing static methods that implement 
 * general algorithms based on objects returned from a data model.
 */
public class Algorithms {

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static int binarySearchWithDuplicates(List data, Object searchItem, Comparator comparator) {
		int index = Collections.binarySearch(data, searchItem, comparator);

		// the binary search returns a negative, incremented position if there is no match in the
		// list for the given search
		if (index < 0) {
			index = -index - 1;
		}
		else {
			index = findTrueStartIndex(searchItem, data, index, comparator);
		}
		return index;
	}

	// finds the index of the first element in the given list--this is used in conjunction with
	// the binary search, which doesn't produce the desired results when searching lists with 
	// duplicates

	private static <T> int findTrueStartIndex(T searchItem, List<T> dataList, int startIndex,
			Comparator<T> comparator) {
		if (startIndex < 0) {
			return startIndex;
		}

		for (int i = startIndex; i >= 0; i--) {
			if (comparator.compare(dataList.get(i), searchItem) != 0) {
				return ++i; // previous index
			}
		}

		return 0; // this means that the search text matches the first element in the lists
	}

	public static <T> void bubbleSort(List<T> data, int low, int high, Comparator<T> comparator) {
		try {
			doBubbleSort(data, low, high, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// do nothing--cancelled
		}
	}

	private static <T> void doBubbleSort(List<T> data, int low, int high, Comparator<T> comparator,
			TaskMonitor monitor) throws CancelledException {
		for (int i = high; i > low; --i) {
			monitor.checkCanceled();

			boolean swapped = false;
			for (int j = low; j < i; j++) {
				if (comparator.compare(data.get(j), data.get(j + 1)) > 0) {
					Collections.swap(data, j, j + 1);
					swapped = true;
				}
			}
			if (!swapped) {
				return;
			}
		}
	}

	public static <T> void mergeSort(List<T> data, Comparator<T> c, TaskMonitor monitor) {
		List<T> aux = new ArrayList<T>(data);
		mergeSort(aux, data, 0, data.size(), c, monitor);
	}

	private static <T> void mergeSort(List<T> src, List<T> dest, int low, int high,
			Comparator<T> c, TaskMonitor monitor) {

		try {
			doMergeSort(src, dest, low, high, c, monitor);
		}
		catch (CancelledException e) {
			// do nothing--cancelled
		}
	}

	private static <T> void doMergeSort(List<T> src, List<T> dest, int low, int high,
			Comparator<T> c, TaskMonitor monitor) throws CancelledException {

		monitor.checkCanceled();

		monitor.setProgress(low);
		int length = high - low;
		if (length < 7) {
			doBubbleSort(dest, low, high - 1, c, monitor);
			return;
		}

		// Recursively sort halves of dest into src
		int mid = (low + high) >> 1;
		doMergeSort(dest, src, low, mid, c, monitor);
		doMergeSort(dest, src, mid, high, c, monitor);

		// If list is already sorted, just copy from src to dest.  This is an
		// optimization that results in faster sorts for nearly ordered lists.
		if (c.compare(src.get(mid - 1), src.get(mid)) <= 0) {
			for (int i = low; i < high; i++) {
				monitor.checkCanceled();
				dest.set(i, src.get(i));
			}
			return;
		}

		// Merge sorted halves (now in src) into dest
		for (int i = low, p = low, q = mid; i < high; i++) {
			monitor.checkCanceled();
			if (q >= high || p < mid && c.compare(src.get(p), src.get(q)) <= 0) {
				dest.set(i, src.get(p++));
			}
			else {
				dest.set(i, src.get(q++));
			}
		}
	}

//	/**
//	 * Performs a quick sort on an array of long values. 
//	 * The entire array is sorted using the provided comparator.
//	 * @param model the index based model containing the data to be searched.
//	 * @param monitor provides feedback about the sort progress and allows user to cancel sort.
//	 * @return true if the qsort completed the sort without being cancelled.
//	 */
//	public static <T> void qsort(List<T> data, Comparator<T> comparator, TaskMonitor monitor) {
//		qsort(data, 0, data.size()-1, comparator, monitor);
//	}
//	/**
//	 * Performs a quick sort on a portion of an array of long values. 
//	 * The array is sorted between the low index and high index inclusive
//	 * using the provided comparator.
//	 * @param model the index based model containing the data to be searched.
//	 * @param low the index for the low side of the range of indexes to sort.
//	 * @param high the index for the high side of the range of indexes to sort.
//	 * @param monitor provides feedback about the sort progress and allows user to cancel sort.
//	 * @return true if the qsort completed the sort without being cancelled.
//	 */
//	public static <T> void qsort(List<T> data, int low, int high, Comparator<T> comparator, TaskMonitor monitor) {
//		if (monitor.isCancelled()) {
//			return;
//		} 
//		if (low+6 > high) {
//			bubbleSort(data, low, high, comparator);
//			return;
//		}
//		if (high <= low) {
//			return;
//		}
//		monitor.setProgress(low);
//		swapMiddleValueToEnd(data, low, high, comparator);
//		Collections.swap(data, (low+high)/2, high);
//		T pivotObj = data.get(high-1);
//
//		int i=low;
//		int j=high;
//		while(i<j) {
//			while(comparator.compare(data.get(++i), pivotObj) < 0){ 
//				if (monitor.isCancelled()) {
//					return;
//				} 
//			} 
//			while(comparator.compare(pivotObj, data.get(--j)) < 0) {
//				if (monitor.isCancelled()) {
//					return;
//				} 
//			} 
//			if (i < j) {
//				Collections.swap(data, i, j);
//			}
//		}
//		Collections.swap(data, i, high);
//		qsort(data, low, i-1, comparator, monitor);
//		qsort(data, i+1, high, comparator, monitor);
//	}
//
//	private static <T> void swapMiddleValueToEnd(List<T> data, int low, int high, Comparator<T> comparator) {
//		int middle = (low+high)/2;
//		if (comparator.compare(data.get(middle), data.get(low)) < 0) {
//			Collections.swap(data, middle, low);
//		}
//		if (comparator.compare(data.get(high), data.get(low)) < 0) {
//			Collections.swap(data, high, low);
//		}
//		if (comparator.compare(data.get(high), data.get(middle)) < 0) {
//			Collections.swap(data, high, middle);
//		}
//		Collections.swap(data, middle, high-1);
//	}	

}
