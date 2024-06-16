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

import ghidra.program.model.address.AddressSet;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Container class for {@link AddressSet}s used during model training and testing
 */
public class TrainingAndTestData {
	private AddressSet trainingPositive;
	private AddressSet trainingNegative;
	private AddressSet testPositive;
	private AddressSet testNegative;

	public TrainingAndTestData(AddressSet trainingPositive, AddressSet trainingNegative,
			AddressSet testPositive, AddressSet testNegative) {
		this.trainingPositive = trainingPositive;
		this.trainingNegative = trainingNegative;
		this.testPositive = testPositive;
		this.testNegative = testNegative;
	}

	/**
	 * Returns the {@link AddressSet} of positive examples for training
	 * @return training positive
	 */
	public AddressSet getTrainingPositive() {
		return trainingPositive;
	}

	/**
	 * Returns the {@link AddressSet} of negative examples for training
	 * @return training negative
	 */
	public AddressSet getTrainingNegative() {
		return trainingNegative;
	}

	/**
	 * Returns the {@link AddressSet} of positive examples for testing
	 * @return test positive
	 */
	public AddressSet getTestPositive() {
		return testPositive;
	}

	/**
	 * Returns the {@link AddressSet} of negative examples for testing
	 * @return test negative
	 */
	public AddressSet getTestNegative() {
		return testNegative;
	}

	/**
	 * Checks the sizes of the sets {@code testPositive} and {@code testNegative}.  Any set
	 * that is larger than {@code max} is replaced with a random subset of size {@code max}.
	 * 
	 * @param max max size of each set
	 * @param monitor task monitor
	 * @throws CancelledException if the monitor is canceled
	 */
	public void reduceTestSetSize(long max, TaskMonitor monitor) throws CancelledException {
		if (testPositive.getNumAddresses() > max) {
			testPositive = RandomSubsetUtils.randomSubset(testPositive, max, monitor);
		}
		if (testNegative.getNumAddresses() > max) {
			testNegative = RandomSubsetUtils.randomSubset(testNegative, max, monitor);
		}
	}

}
