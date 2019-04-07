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
package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitorAdapter;

public class AlgorithmsTest extends AbstractGenericTest {
	Comparator<Long> comparator;

	public AlgorithmsTest() {
		super();
		comparator = new Comparator<Long>() {
			@Override
			public int compare(Long a, Long b) {
				if (a < b) {
					return -1;
				}
				else if (a > b) {
					return 1;
				}
				return 0;
			}
		};

	}

	private List<Long> getList(long[] data) {
		List<Long> list = new ArrayList<Long>(data.length);
		for (int i = 0; i < data.length; i++) {
			list.add(data[i]);
		}
		return list;
	}

	@Test
	public void testBubbleSort() {
		List<Long> data = getList(new long[] { 5, 8, 10, 2, 10, 3, 3, 7, 10, 23, 0, 15, 22 });
		int low = 3;
		int high = 8;
		Algorithms.bubbleSort(data, low, high, comparator);
		long[] expected = new long[] { 5, 8, 10, 2, 3, 3, 7, 10, 10, 23, 0, 15, 22 };
		for (int i = 0; i < expected.length; i++) {
			assertEquals(new Long(expected[i]), data.get(i));
		}
	}

	@Test
	public void testmergeSort() {
		List<Long> data = getList(new long[] { 5, 8, 10, 2, 10, 3, 3, 7, 10, 23, 0, 15, 22 });
		Algorithms.mergeSort(data, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		long[] expected = new long[] { 0, 2, 3, 3, 5, 7, 8, 10, 10, 10, 15, 22, 23 };
		for (int i = 0; i < expected.length; i++) {
			assertEquals(new Long(expected[i]), data.get(i));
		}
	}

	@Test
	public void testmergeSort2() {
		List<Long> data = getList(new long[] { 0, 1, 2, 3, 4, 0, 0, 0 });
		Algorithms.mergeSort(data, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		long[] expected = new long[] { 0, 0, 0, 0, 1, 2, 3, 4 };
		for (int i = 0; i < expected.length; i++) {
			assertEquals(new Long(expected[i]), data.get(i));
		}
	}

	@Test
	public void testmergeSort3() {
		List<Long> data = getList(new long[] { 0, 1, 2, 3, 4, 4, 4, 4 });
		Algorithms.mergeSort(data, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		long[] expected = new long[] { 0, 1, 2, 3, 4, 4, 4, 4 };
		for (int i = 0; i < expected.length; i++) {
			assertEquals(new Long(expected[i]), data.get(i));
		}
	}

	@Test
	public void testmergeSort4() {
		List<Long> data = getList(new long[] { 1, 1, 1, 1, 1, 1, 1, 1 });
		Algorithms.mergeSort(data, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		long[] expected = new long[] { 1, 1, 1, 1, 1, 1, 1, 1 };
		for (int i = 0; i < expected.length; i++) {
			assertEquals(new Long(expected[i]), data.get(i));
		}
	}

	@Test
	public void testmergeSort5() {
		long[] l = new long[100000];
		Random r = new Random();
		for (int i = 0; i < l.length; i++) {
			l[i] = r.nextLong();
		}
		List<Long> data = getList(l);

		Algorithms.mergeSort(data, comparator, TaskMonitorAdapter.DUMMY_MONITOR);
		for (int i = 0; i < l.length - 1; i++) {
			assertTrue("i = " + i, data.get(i) <= data.get(i + 1));
		}
	}

	@Test
	public void testBinarySearch() {
		List<Long> data = getList(new long[] { 0, 2, 3, 3, 5, 7, 8, 10, 10, 10, 15, 22, 23 });

		assertEquals(0, Collections.binarySearch(data, new Long(0)));
		assertEquals(4, Collections.binarySearch(data, new Long(5)));
		assertEquals(12, Collections.binarySearch(data, new Long(23)));
		assertEquals(-8, Collections.binarySearch(data, new Long(9)));
		assertEquals(-1, Collections.binarySearch(data, new Long(-12)));
		assertEquals(-14, Collections.binarySearch(data, new Long(50)));

	}

}
