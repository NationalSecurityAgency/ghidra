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

import org.tribuo.Feature;
import org.tribuo.Prediction;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.impl.ArrayExample;

import generic.concurrent.QCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link QCallback} which is used to apply a model at a given address to determine the
 * probability that the address represents a function start.
 */
class FunctionStartCallback implements QCallback<Address, Double> {

	private EnsembleModel<Label> randomForest;
	private int numPreBytes;
	private int numInitialBytes;
	private Program program;
	private int alignment;
	private Label target;
	private boolean includeBitLevelFeatures;

	/**
	 * Creates a callback which applies {@code model} to addresses in {@code program} using
	 * the data-gathering parameters {@code numPreBytes} and {@code numInitialBytes} to
	 * determine the probability the address has label {@label}. 
	 * @param model model to apply
	 * @param numPreBytes bytes before address to gather
	 * @param numInitialBytes bytes after address to gather
	 * @param includeBitLevelFeatures whether to include bit-level features
	 * @param program source program
	 * @param target target label
	 */
	public FunctionStartCallback(EnsembleModel<Label> model, int numPreBytes, int numInitialBytes,
			boolean includeBitLevelFeatures, Program program, Label target) {
		this.randomForest = model;
		this.numPreBytes = numPreBytes;
		this.numInitialBytes = numInitialBytes;
		this.program = program;
		alignment = program.getLanguage().getInstructionAlignment();
		this.target = target;
		this.includeBitLevelFeatures = includeBitLevelFeatures;
	}

	@Override
	public Double process(Address item, TaskMonitor monitor) throws Exception {
		if (Long.remainderUnsigned(item.getOffset(), alignment) != 0) {
			return null;
		}
		List<Feature> vecToClassify = ModelTrainingUtils.getFeatureVector(program, item,
			numPreBytes, numInitialBytes, includeBitLevelFeatures);
		ArrayExample<Label> vec =
			new ArrayExample<>(LabelFactory.UNKNOWN_LABEL, vecToClassify);

		if (vec.size() == 0) {
			return null;
		}
		Prediction<Label> pred = randomForest.predict(vec);
		return pred.getOutputScores().get(target.getLabel()).getScore();
	}
}
