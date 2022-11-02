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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.TestAddress;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RandomSubsetTest extends AbstractGenericTest {

	@Test
	public void testGenerateTrivialSubsets() {
		List<Long> empty = RandomSubsetUtils.generateRandomIntegerSubset(10, 0);
		assertEquals(0, empty.size());
		empty = RandomSubsetUtils.generateRandomIntegerSubset(0, 0);
		assertEquals(0, empty.size());
		List<Long> complete = RandomSubsetUtils.generateRandomIntegerSubset(1000000, 1000000);
		Collections.sort(complete);
		Iterator<Long> iter = complete.iterator();
		long current = 0;
		while (iter.hasNext()) {
			long elem = iter.next();
			assertEquals(current++, elem);
		}
	}

	@Test
	public void testBasicRandomSubsetOfAddresses() throws CancelledException {
		AddressSet addrs = new AddressSet();
		for (long i = 0; i < 10000; ++i) {
			addrs.add(new TestAddress(i));
		}
		AddressSet rand = RandomSubsetUtils.randomSubset(addrs, 9998, TaskMonitor.DUMMY);
		assertEquals(9998, rand.getNumAddresses());
	}

	@Test
	public void testSwap() {
		Map<Long, Long> permuted = new HashMap<>();
		assertTrue(permuted.isEmpty());
		//should do nothing
		RandomSubsetUtils.swap(permuted, 1, 1);
		assertTrue(permuted.isEmpty());
		permuted.put(0l, 5l);
		permuted.put(1l, 10l);
		RandomSubsetUtils.swap(permuted, 0, 1);
		assertEquals(2, permuted.size());
		assertEquals(Long.valueOf(5), permuted.get(1l));
		assertEquals(Long.valueOf(10), permuted.get(0l));
		RandomSubsetUtils.swap(permuted, 100l, 200L);
		assertEquals(4, permuted.size());
		assertEquals(Long.valueOf(100), permuted.get(200l));
		assertEquals(Long.valueOf(200), permuted.get(100l));
	}

	/**
	@Test
	public void timingTest() throws CancelledException {
		AddressSet big = new AddressSet(new TestAddress(0), new TestAddress(999999));
	
		long start = System.nanoTime();
		List<Long> complete = RandomSubset.generateRandomIntegerSubset(1000000, 500000);
		long end = System.nanoTime();
		Msg.info(this, "choosing random subset of integers: " +
			(end - start) / RandomForestTrainingTask.NANOSECONDS_PER_SECOND);
		start = System.nanoTime();
		AddressSet random = RandomSubset.randomSubset(big, 500000, TaskMonitor.DUMMY);
		end = System.nanoTime();
		Msg.info(this, "choosing random subset of addresses: " +
			(end - start) / RandomForestTrainingTask.NANOSECONDS_PER_SECOND);
	}*/

}
