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

import java.util.List;

import org.tribuo.*;
import org.tribuo.classification.Label;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.impl.ArrayExample;

import generic.concurrent.QCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * This class is used as a callback for parallelized ensemble evaluation.  Rather than
 * computing the precise probability the ensemble would assign to a given address and label,
 * it only computes whether the probability is >= .5.  The computation is short-circuited:
 * as soon as enough members of the ensemble have been checked to determine the return value
 * the computation stops.
 */
public class EnsembleEvaluatorCallback implements QCallback<Address, Boolean> {

	private EnsembleModel<Label> ensemble;
	private int numModels;
	private int numPreBytes;
	private int numInitialBytes;
	private Label label;
	private Program program;
	private boolean includeBitFeatures;

	/**
	 * Create a new evaluator
	 * @param ensemble ensemble to evaluate
	 * @param p program containing addresses to test
	 * @param numPreBytes number of bytes before address
	 * @param numInitialBytes number of bytes after and including address
	 * @param includeBitFeatures whether to include bit-level features
	 * @param label target label
	 */
	public EnsembleEvaluatorCallback(EnsembleModel<Label> ensemble, Program p, int numPreBytes,
			int numInitialBytes, boolean includeBitFeatures, Label label) {
		this.ensemble = ensemble;
		numModels = ensemble.getNumModels();
		this.numPreBytes = numPreBytes;
		this.numInitialBytes = numInitialBytes;
		this.label = label;
		program = p;
		this.includeBitFeatures = includeBitFeatures;
	}

	@Override
	public Boolean process(Address item, TaskMonitor monitor) throws Exception {
		List<Feature> trainingVector = ModelTrainingUtils.getFeatureVector(program, item,
			numPreBytes, numInitialBytes, includeBitFeatures);
		if (trainingVector.isEmpty()) {
			return null;
		}
		ArrayExample<Label> vec = new ArrayExample<>(label, trainingVector);

		int numAgree = 0;
		int numDisagree = 0;
		for (int i = 0; i < numModels; i++) {
			Model<Label> model = ensemble.getModels().get(i);
			Prediction<Label> pred = model.predict(vec);
			if (pred.getOutput().equals(label)) {
				numAgree += 1;
			}
			else {
				numDisagree += 1;
			}
			if (numAgree == (numModels + 1) / 2) {
				return true;
			}
			if (numDisagree == (numModels / 2) + 1) {
				return false;
			}
		}
		throw new AssertionError("did not return value");
	}

}
