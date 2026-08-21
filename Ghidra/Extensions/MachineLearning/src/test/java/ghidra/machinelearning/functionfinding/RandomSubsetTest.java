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
package ghidra.machinelearning.functionfinding;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.pcodeCPort.utils.MutableLong;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RandomSubsetTest extends AbstractGenericTest {

	@Test
	public void testGenerateTrivialSubsets() {
		long[] empty = RandomSubsetUtils.generateRandomIntegerSubset(10, 0);
		assertEquals(0, empty.length);
		empty = RandomSubsetUtils.generateRandomIntegerSubset(0, 0);
		assertEquals(0, empty.length);
		long[] complete = RandomSubsetUtils.generateRandomIntegerSubset(1000000, 1000000);
		Arrays.sort(complete);
		for (int current = 0; current < complete.length; current++) {
			long elem = complete[current];
			assertEquals(current, elem);
		}
	}

	@Test
	public void testBasicRandomSubsetOfAddresses() throws CancelledException {
		// Check we are drawing unique addresses from the set
		AddressSet addrs = new AddressSet();
		for (long i = 0; i < 10000; ++i) {
			addrs.add(new TestAddress(i));
		}
		AddressSet rand = RandomSubsetUtils.randomSubset(addrs, 9998, TaskMonitor.DUMMY);
		assertEquals(9998, rand.getNumAddresses());

		addrs.clear();

		// Check we correctly draw from multiple non-contiguous ranges
		for (long i = 0; i < 10000; i += 1000) {
			if (i % 2000 != 0)
				continue;
			for (long j = i; j < i + 1000; j++) {
				addrs.add(new TestAddress(j));
			}
		}
		rand = RandomSubsetUtils.randomSubset(addrs, 4998, TaskMonitor.DUMMY);
		assertEquals(4998, rand.getNumAddresses());

		for (Address addr : rand.getAddresses(true)) {
			assertTrue(addrs.contains(addr));
		}
	}

	@Test
	public void testSwap() {
		Map<Long, MutableLong> permuted = new HashMap<>();
		assertTrue(permuted.isEmpty());
		//should do nothing
		RandomSubsetUtils.swap(permuted, 1, 1);
		assertTrue(permuted.isEmpty());
		permuted.put(0l, new MutableLong(5l));
		permuted.put(1l, new MutableLong(10l));
		RandomSubsetUtils.swap(permuted, 0, 1);
		assertEquals(2, permuted.size());
		assertEquals(5l, permuted.get(1l).get());
		assertEquals(10l, permuted.get(0l).get());
		RandomSubsetUtils.swap(permuted, 100l, 200L);
		assertEquals(4, permuted.size());
		assertEquals(100l, permuted.get(200l).get());
		assertEquals(200l, permuted.get(100l).get());
	}

//	@Test
//	public void timingTest() throws CancelledException, InterruptedException {
//		AddressSet big = new AddressSet(new TestAddress(0), new TestAddress(9999999));
//
//		Thread.sleep(10000);
//		long start;
//		long end;
//
//		for (int i = 0; i < 10; i++) {
//			start = System.nanoTime();
//			long[] complete = RandomSubsetUtils.generateRandomIntegerSubset(10000000, 5000000);
//			end = System.nanoTime();
//			Msg.info(this, "choosing random subset of integers: " +
//				(end - start) / RandomForestTrainingTask.NANOSECONDS_PER_SECOND);
//		}
//
//		for (int i = 0; i < 10; i++) {
//			start = System.nanoTime();
//			AddressSet random1 = RandomSubsetUtils.randomSubset(big, 5000000, TaskMonitor.DUMMY);
//			end = System.nanoTime();
//			Msg.info(this, "choosing random subset of addresses: " +
//				(end - start) / RandomForestTrainingTask.NANOSECONDS_PER_SECOND);
//		}
//	}

}
