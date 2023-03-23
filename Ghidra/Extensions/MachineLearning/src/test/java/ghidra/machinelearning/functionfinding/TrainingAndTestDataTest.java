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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.TestAddress;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TrainingAndTestDataTest extends AbstractGenericTest {

	private TrainingAndTestData data;
	private AddressSet originalPos;
	private AddressSet originalNeg;

	@Before
	public void setUp() {
		AddressSet testPositive = new AddressSet();
		testPositive.add(new TestAddress(0), new TestAddress(100));
		originalPos = new AddressSet(testPositive);
		AddressSet testNegative = new AddressSet();
		testNegative.add(new TestAddress(500), new TestAddress(1000));
		originalNeg = new AddressSet(testNegative);
		data =
			new TrainingAndTestData(new AddressSet(), new AddressSet(), testPositive, testNegative);
	}

	@Test
	public void reduceTest1() throws CancelledException {
		data.reduceTestSetSize(1001, TaskMonitor.DUMMY);
		assertTrue(data.getTestPositive().hasSameAddresses(originalPos));
		assertTrue(data.getTestNegative().hasSameAddresses(originalNeg));
	}

	@Test
	public void reduceTest2() throws CancelledException {
		data.reduceTestSetSize(250, TaskMonitor.DUMMY);
		assertTrue(data.getTestPositive().hasSameAddresses(originalPos));
		assertEquals(250, data.getTestNegative().getNumAddresses());
	}

	@Test
	public void reduceTest3() throws CancelledException {
		data.reduceTestSetSize(10, TaskMonitor.DUMMY);
		assertEquals(10, data.getTestPositive().getNumAddresses());
		assertEquals(10, data.getTestNegative().getNumAddresses());
	}

}
