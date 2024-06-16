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

import java.util.*;

import org.tribuo.classification.Label;
import org.tribuo.ensemble.EnsembleModel;

import generic.concurrent.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class uses a {@link GThreadPool} to execute a {@link FunctionStartCallback} in
 * parallel in order to classify addresses in a program as function starts or non-starts.
 */
public class FunctionStartClassifier {

	private static final double DEFAULT_PROB_THRESHOLD = 0.5d;

	private Program program;
	private RandomForestRowObject modelRow;
	private double probabilityThreshold;
	private Label target;

	/**
	 * Creates an object used to apply the model in {@code modelRow} to addresses in {@code program}
	 * to the probability of having label {@code target}.
	 * @param program program to check
	 * @param modelRow row containing model and data gathering parameters
	 * @param target target addresses
	 */
	public FunctionStartClassifier(Program program, RandomForestRowObject modelRow, Label target) {
		this.program = program;
		this.modelRow = modelRow;
		probabilityThreshold = DEFAULT_PROB_THRESHOLD;
		this.target = target;
	}

	/**
	 * Sets the probability threshold.  Address where the probability of having the target
	 * label is less than the threshold are not included in the map returned by 
	 * {@link FunctionStartClassifier#classify(AddressSetView, TaskMonitor)}
	 * @param thresh new threshold
	 */
	public void setProbabilityThreshold(double thresh) {
		probabilityThreshold = thresh;
	}

	/**
	 * Classifies the addresses in {@code addresses} in parallel.
	 * @param addresses addresses to classify
	 * @param monitor monitor
	 * @return map from addresses to probabilities
	 * @throws CancelledException if monitor is canceled
	 */
	public Map<Address, Double> classify(AddressSetView addresses, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(addresses.getNumAddresses());
		int preBytes = modelRow.getNumPreBytes();
		int initialBytes = modelRow.getNumInitialBytes();
		EnsembleModel<Label> randomForest = modelRow.getRandomForest();
		Msg.info(this, "Number of addresses to classify: " + addresses.getNumAddresses());
		GThreadPool threadPool = GThreadPool.getSharedThreadPool("FunctionStartClassifier");

		ConcurrentQBuilder<Address, Double> classifyBuilder = new ConcurrentQBuilder<>();
		ConcurrentQ<Address, Double> classifyQ = classifyBuilder.setThreadPool(threadPool)
				.setCollectResults(true)
				.setMonitor(monitor)
				.build(new FunctionStartCallback(randomForest, preBytes, initialBytes,
					modelRow.getIncludeBitLevelFeatures(), program, target));
		classifyQ.add(addresses.getAddresses(true));
		Collection<QResult<Address, Double>> results = Collections.emptyList();
		long start = System.nanoTime();
		try {
			results = classifyQ.waitForResults();
		}
		catch (InterruptedException e) {
			monitor.checkCancelled();
			Msg.error(this, "Exception while classifying functions: " + e.getMessage());
		}
		long end = System.nanoTime();
		Msg.info(this, String.format("Classification time: %g seconds",
			(end - start) / RandomForestTrainingTask.NANOSECONDS_PER_SECOND));
		Map<Address, Double> addrToProb = new HashMap<>();
		for (QResult<Address, Double> result : results) {
			Double score = null;
			try {
				score = result.getResult();
			}
			catch (Exception e) {
				Msg.error(this, "Problem  getting score of Address " + result.getItem() + ": " +
					e.getMessage());
				continue;
			}
			if (score != null && score >= probabilityThreshold) {
				addrToProb.put(result.getItem(), score);
			}
		}
		return addrToProb;
	}
}
