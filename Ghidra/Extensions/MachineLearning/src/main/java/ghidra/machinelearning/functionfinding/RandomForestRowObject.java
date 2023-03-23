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

import java.math.*;
import java.util.Collections;
import java.util.List;

import org.tribuo.classification.Label;
import org.tribuo.ensemble.EnsembleModel;

import ghidra.program.model.address.AddressSet;

/**
 * A class for row objects in a table whose rows are associated with models trained to
 * find function starts.  Some of the fields of this class are used to populate these
 * rows with data about how accurate the model was on the test set.  Other fields 
 * (such as {@code numPreBytes}, {@code numInitialBytes}, and {@code includeBitLevelFeatures})
 * are needed by actions defined on this table apply the model (and thus must know how
 * to generate feature vectors the model consumes).
 */
public class RandomForestRowObject {

	private BigDecimal precision;
	private BigDecimal recall;
	private int numPreBytes;
	private int numInitialBytes;
	private int samplingFactor;
	private boolean includeBitLevelFeatures;
	private List<String> contextRegisters;
	private List<BigInteger> contextRegisterValues;
	private EnsembleModel<Label> randomForest;
	private AddressSet testErrors;
	private AddressSet trainingPositive;
	private int[] confusionMatrix;

	/**
	 * Constructs a row
	 * @param numPreBytes number of prebytes in vectors consumed by model
	 * @param numInitialBytes number of initialBytes in vectors consumed by model
	 * @param samplingFactor non-start to start sampling factor
	 * @param confusionMatrix confusion matrix of model on test set
	 * @param randomForest model
	 * @param testErrors set of addresses in test set with errors
	 * @param trainingPositive set of positive training examples (i.e. function starts)
	 * @param includeBitLevelFeatures whether bit-level features were included in model
	 */
	public RandomForestRowObject(int numPreBytes, int numInitialBytes, int samplingFactor,
			int[] confusionMatrix, EnsembleModel<Label> randomForest, AddressSet testErrors,
			AddressSet trainingPositive, boolean includeBitLevelFeatures) {
		this.numPreBytes = numPreBytes;
		this.numInitialBytes = numInitialBytes;
		this.samplingFactor = samplingFactor;
		this.randomForest = randomForest;
		this.testErrors = testErrors;
		this.contextRegisters = Collections.emptyList();
		this.contextRegisterValues = Collections.emptyList();
		this.confusionMatrix = confusionMatrix;
		this.includeBitLevelFeatures = includeBitLevelFeatures;
		BigDecimal numerator = new BigDecimal(confusionMatrix[RandomForestTrainingTask.TP]);
		BigDecimal denominator = new BigDecimal(confusionMatrix[RandomForestTrainingTask.TP] +
			confusionMatrix[RandomForestTrainingTask.FP]);
		if (denominator.equals(BigDecimal.ZERO)) {
			precision = null;
		}
		else {
			precision = numerator.divide(denominator, 2, RoundingMode.HALF_EVEN);
		}
		denominator = new BigDecimal(confusionMatrix[RandomForestTrainingTask.TP] +
			confusionMatrix[RandomForestTrainingTask.FN]);
		if (denominator.equals(BigDecimal.ZERO)) {
			recall = null;
		}
		else {
			recall = numerator.divide(denominator, 2, RoundingMode.HALF_EVEN);
		}
		this.trainingPositive = trainingPositive;
	}

	/**
	 * Sets the values for context register the model is aware of
	 * @param regList register names
	 * @param valueList register values 
	 */
	public void setContextRegistersAndValues(List<String> regList, List<BigInteger> valueList) {
		if (regList.size() != valueList.size()) {
			throw new IllegalArgumentException(
				"Register list and value list must have the same size!");
		}
		contextRegisters = List.copyOf(regList);
		contextRegisterValues = List.copyOf(valueList);
	}

	/**
	 * Returns a boolean indicating whether the model is aware of any context registers
	 * @return aware of context
	 */
	public boolean isContextRestricted() {
		return !contextRegisters.isEmpty();
	}

	/**
	 * Returns the names of the context registers the model is aware of
	 * @return context reg names
	 */
	public List<String> getContextRegisterList() {
		return contextRegisters;
	}

	/**
	 * Returns the list of values of context registers the model is aware of
	 * @return context reg values
	 */
	public List<BigInteger> getContextRegisterValues() {
		return contextRegisterValues;
	}

	/**
	 * Returns the precision of the model on the test set
	 * @return precision
	 */
	public BigDecimal getPrecision() {
		return precision;
	}

	/**
	 * Returns the recall of the model on the test set
	 * @return recall
	 */
	public BigDecimal getRecall() {
		return recall;
	}

	/**
	 * Returns a boolean indicating whether bit-level features were included when training the model
	 * @return bit-level features used
	 */
	public boolean getIncludeBitLevelFeatures() {
		return includeBitLevelFeatures;
	}

	/**
	 * Returns the number of pre-bytes used when training the model
	 * @return pre-bytes
	 */
	public int getNumPreBytes() {
		return numPreBytes;
	}

	/**
	 * Returns the sampling factor used when training the model
	 * @return sampling factor
	 */
	public int getSamplingFactor() {
		return samplingFactor;
	}

	/**
	 * Returns the number of initial bytes used when training the model
	 * @return num initial bytes
	 */
	public int getNumInitialBytes() {
		return numInitialBytes;
	}

	/**
	 * Returns the model
	 * @return model
	 */
	public EnsembleModel<Label> getRandomForest() {
		return randomForest;
	}

	/**
	 * Returns the addresses in the test set where the model made an error
	 * @return error set
	 */
	public AddressSet getTestErrors() {
		return testErrors;
	}

	/**
	 * Returns the number of false positives the model produces when classifying the test set.
	 * @return num false positives
	 */
	public int getNumFalsePositives() {
		return confusionMatrix[RandomForestTrainingTask.FP];
	}

	/**
	 * Returns the set of function starts in the training set.
	 * @return known starts
	 */
	public AddressSet getTrainingPositives() {
		return trainingPositive;
	}
}
