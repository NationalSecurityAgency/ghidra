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
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Consumer;

import org.tribuo.*;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.classification.dtree.CARTClassificationTrainer;
import org.tribuo.classification.ensemble.VotingCombiner;
import org.tribuo.common.tree.TreeModel;
import org.tribuo.dataset.DatasetView;
import org.tribuo.datasource.ListDataSource;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.ensemble.WeightedEnsembleModel;
import org.tribuo.provenance.SimpleDataSourceProvenance;

import generic.concurrent.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * This {@link Task} is used to train and evaluate random forests.
 */
public class RandomForestTrainingTask extends Task {

	//NUM_TREES should be odd to avoid nuances involving tiebreaking
	public static final int NUM_TREES = 99;
	public static final String TITLE = "Training Model for ";
	public static final int MAX_EVAL_SET_SIZE = 50000;
	public static final String RANDOM_FOREST_TRAINING_THREADPOOL = "RandomForestTrainer";
	public static final double NANOSECONDS_PER_SECOND = 1000000000.0d;

	//for the confusion matrix
	public static final int TP = 0;
	public static final int FP = 1;
	public static final int TN = 2;
	public static final int FN = 3;
	public static final int CONFUSION_MATRIX_SIZE = 4;

	private FunctionStartRFParams params;
	private Program program;
	//trainingSet is accessed from different threads during training
	private Dataset<Label> trainingSet;
	private Consumer<RandomForestRowObject> rowObjectConsumer;
	private AddressSet additionalStarts;
	private AddressSet additionalNonStarts;
	private Long testSetMax;

	/**
	 * Creates a {@link Task} for training (and evaluating) random forests for function
	 * start identification.
	 *	  
	 * @param program source of training
	 * @param params parameters controlling training
	 * @param rowObjectConsumer consumes data about the trained models
	 * @param testSetMax maximum size of test sets
	 */
	public RandomForestTrainingTask(Program program, FunctionStartRFParams params,
			Consumer<RandomForestRowObject> rowObjectConsumer, long testSetMax) {
		super(TITLE + program.getName(), true, true, false, false);
		this.program = program;
		this.params = params;
		this.rowObjectConsumer = rowObjectConsumer;
		this.testSetMax = testSetMax;
		additionalStarts = new AddressSet();
		additionalNonStarts = new AddressSet();
	}

	/**
	 * Adds a {@ProgramSelection} to the training set. Function starts within the selection are
	 * added as positive examples and everything else is added as a negative example.
	 *
	 *<p>
	 * Addresses which are not aligned or which do not agree with the context register values
	 * in the {@code params} variable of the constructor are ignored.
	 * @param selection selection to add
	 * @return number of aligned addresses conflicting with the context register data specified in
	 * {@code params}
	 */
	public int setAdditional(ProgramSelection selection) {
		if (selection == null) {
			return 0;
		}
		int numConflicts = 0;
		int instructionAlignment = program.getLanguage().getInstructionAlignment();
		for (Address addr : selection.getAddresses(true)) {
			if (addr.getOffset() % instructionAlignment != 0) {
				continue;
			}
			if (params.isRestrictedByContext()) {
				if (!params.isContextCompatible(addr)) {
					numConflicts += 1;
					continue;
				}
			}
			if (program.getFunctionManager().getFunctionAt(addr) == null) {
				additionalNonStarts.add(addr);
			}
			else {
				additionalStarts.add(addr);
			}
		}
		return numConflicts;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setIndeterminate(true);
		monitor.setMessage("Gathering function entries and interiors");

		//get all the function entries and interiors that are consistent
		//with the requirements in params
		params.computeFuncEntriesAndInteriors(monitor);
		AddressSet allEntries = params.getFuncEntries();
		AddressSet allInteriors = params.getFuncInteriors();

		//defined data in executable sections will be added to the test set
		AddressSet definedData = ModelTrainingUtils.getDefinedData(program, monitor);

		for (Integer factor : params.getSamplingFactors()) {
			//get the addresses used for training and testing
			TrainingAndTestData data =
				getTrainingAndTestData(allEntries, allInteriors, definedData, factor, monitor);
			if (data == null) {
				continue;
			}
			data.reduceTestSetSize(testSetMax, monitor);
			monitor.setIndeterminate(false);
			for (Integer preBytes : params.getPreBytes()) {
				for (Integer initialBytes : params.getInitialBytes()) {
					Msg.info(this,
						String.format(
							"Data Gathering Parameters: factor: %d preBytes: %s initialBytes: %d",
							factor, preBytes, initialBytes));

					//create the vectors for the training addresses
					List<Example<Label>> trainingData = new ArrayList<>();
					monitor.setMessage("Generating vectors for function entries");
					trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program,
						data.getTrainingPositive(), RandomForestFunctionFinderPlugin.FUNC_START,
						preBytes, initialBytes, params.getIncludeBitFeatures(), monitor));
					monitor.setMessage("Generating vectors for function interiors");
					trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program,
						data.getTrainingNegative(), RandomForestFunctionFinderPlugin.NON_START,
						preBytes, initialBytes, params.getIncludeBitFeatures(), monitor));

					//should only happen with very small training sets where MemoryAccessExceptions
					//were thrown during vector generation
					if (trainingData.isEmpty()) {
						Msg.showWarn(this, null, "Empty Training Set", String.format(
							"No vectors were generated for supplied addresses.  preBytes = %d, " +
								"initialBytes = %d",
							preBytes, initialBytes));
						continue;
					}

					//train the model
					EnsembleModel<Label> randomForest = trainModel(trainingData, monitor);

					//evaluate the model and create a RandomForestRowObject
					AddressSet errors = new AddressSet();
					int[] confusionMatrix = evaluateModel(randomForest, data.getTestPositive(),
						data.getTestNegative(), errors, preBytes, initialBytes, monitor);
					if (!monitor.isCancelled()) {
						RandomForestRowObject row = new RandomForestRowObject(preBytes,
							initialBytes, factor, confusionMatrix, randomForest, errors,
							data.getTrainingPositive(), params.getIncludeBitFeatures());
						row.setContextRegistersAndValues(params.getContextRegisterNames(),
							params.getContextRegisterVals());
						rowObjectConsumer.accept(row);
					}
				}
			}
		}
	}

	/**
	 * Creates the training and test sets
	 * @param allEntries function entries
	 * @param allInteriors function interiors
	 * @param definedData defined data
	 * @param factor sampling factor
	 * @param monitor task monitor
	 * @return training and test sets
	 * @throws CancelledException if monitor is canceled
	 */
	TrainingAndTestData getTrainingAndTestData(AddressSet allEntries, AddressSet allInteriors,
			AddressSet definedData, int factor, TaskMonitor monitor) throws CancelledException {
		//if the user has specified addresses to use in training,
		//don't allow those addresses to also be selected at random
		AddressSet selectableEntries = allEntries.subtract(additionalStarts);
		AddressSet selectableInteriors = allInteriors.subtract(additionalNonStarts);
		AddressSet trainingPositive = new AddressSet(additionalStarts);
		AddressSet trainingNegative = new AddressSet(additionalNonStarts);

		//select function entries at random and add them to the training set
		long numEntries =
			(int) Math.min(params.getMaxStarts(), selectableEntries.getNumAddresses());
		monitor.setIndeterminate(true);
		monitor.setMessage("Selecting " + numEntries + " random function entries");
		long start = System.nanoTime();
		AddressSetView randomFuncEntries =
			RandomSubsetUtils.randomSubset(selectableEntries, numEntries, monitor);
		long end = System.nanoTime();
		Msg.info(this, String.format("factor: %d elapsed selecting random entries: %g", factor,
			(end - start) / NANOSECONDS_PER_SECOND));
		trainingPositive = trainingPositive.union(randomFuncEntries);
		if (trainingPositive.isEmpty()) {
			Msg.showError(this, null, "Data Gathering Error", "No functions in training set");
			return null;
		}
		//function entries that weren't selected are used for testing
		AddressSet testPositive = selectableEntries.subtract(randomFuncEntries);
		if (testPositive.isEmpty()) {
			Msg.showWarn(this, null, "Test Set Warning",
				"No function entries in test set for models with sampling factor " + factor);
		}
		//for the randomly-selected function entries, optionally add the immediately 
		//preceding and following code units to the training and test sets as negative examples
		AddressSet immediatelyPrecedingTraining = new AddressSet();
		AddressSet immediatelyFollowingTraining = new AddressSet();
		AddressSet immediatelyPrecedingTest = new AddressSet();
		AddressSet immediatelyFollowingTest = new AddressSet();
		if (params.getIncludePrecedingAndFollowing()) {
			immediatelyPrecedingTraining =
				ModelTrainingUtils.getPrecedingAddresses(program, randomFuncEntries, monitor);
			immediatelyFollowingTraining =
				ModelTrainingUtils.getFollowingAddresses(program, randomFuncEntries, monitor);
			immediatelyPrecedingTest =
				ModelTrainingUtils.getPrecedingAddresses(program, testPositive, monitor);
			immediatelyFollowingTest =
				ModelTrainingUtils.getFollowingAddresses(program, testPositive, monitor);
			//immediatelyPreceding and immediately following can intersect in
			//certain cases; subtract the overlap
			AddressSet before = immediatelyPrecedingTraining.union(immediatelyPrecedingTest);
			AddressSet after = immediatelyFollowingTraining.union(immediatelyFollowingTest);
			immediatelyPrecedingTraining = immediatelyPrecedingTraining.subtract(after);
			immediatelyPrecedingTest = immediatelyPrecedingTest.subtract(after);
			immediatelyFollowingTraining = immediatelyFollowingTraining.subtract(before);
			immediatelyFollowingTest = immediatelyFollowingTest.subtract(before);
			//Since immediatelyFollowingXand immediatelyPrecedingX are explicitly
			//added to the training/test sets, remove them from the set of interiors which could be
			//randomly selected for inclusion in the training set
			selectableInteriors = selectableInteriors
					.subtract(immediatelyFollowingTraining.union(immediatelyPrecedingTraining));
			selectableInteriors = selectableInteriors
					.subtract(immediatelyFollowingTest.union(immediatelyPrecedingTest));
			//remove before and after from definedData
			definedData = definedData.subtract(before.union(after));
		}
		trainingNegative = trainingNegative
				.union(immediatelyPrecedingTraining.union(immediatelyFollowingTraining));

		//now select random function interiors and add them to training set 
		monitor.setMessage(
			"Selecting " + numEntries * factor + " random addresses within function interiors");
		start = System.nanoTime();
		long numInteriors = numEntries * factor;

		AddressSetView randomFuncInteriors = numInteriors < selectableInteriors.getNumAddresses()
				? RandomSubsetUtils.randomSubset(selectableInteriors, numInteriors, monitor)
				: selectableInteriors;
		end = System.nanoTime();
		Msg.info(this, String.format("factor: %d elapsed selecting random interiors: %g seconds",
			factor, (end - start) / NANOSECONDS_PER_SECOND));
		trainingNegative = trainingNegative.union(randomFuncInteriors);
		if (trainingNegative.isEmpty()) {
			Msg.showError(this, null, "Data Gathering Error",
				"No non-starts in training set for sampling factor " + factor);
			return null;
		}
		if (trainingPositive.intersects(trainingNegative)) {
			Address first = trainingPositive.findFirstAddressInCommon(trainingNegative);
			Msg.showWarn(this, null, "Overlap between Training Positive and Training Negative Sets",
				"Example: " + first.toString());
		}
		AddressSet unusedInteriors = selectableInteriors.subtract(randomFuncInteriors);
		AddressSet testNegative = unusedInteriors.union(definedData);
		testNegative = testNegative.union(immediatelyPrecedingTest).union(immediatelyFollowingTest);
		if (testNegative.isEmpty()) {
			Msg.showWarn(this, null, "Test Set Warning",
				"No function interiors in test set for models with sampling factor " + factor);
		}
		if (testPositive.intersects(testNegative)) {
			Address first = testPositive.findFirstAddressInCommon(testNegative);
			Msg.showWarn(this, null, "Overlapping Test Positive and Negative sets",
				"Example: " + first.toString());
		}
		if ((trainingPositive.union(trainingNegative)
				.intersects(testPositive.union(testNegative)))) {
			Address first = trainingPositive.union(trainingNegative)
					.findFirstAddressInCommon(testPositive.union(testNegative));
			Msg.showWarn(this, null, "Overlapping Training and Test Sets",
				"Example: " + first.toString());
		}
		return new TrainingAndTestData(trainingPositive, trainingNegative, testPositive,
			testNegative);
	}

	/**
	 * Trains a model to recognize function entries.  Training is performed in parallel.
	 * @param trainingData training vectors
	 * @param monitor task monitor
	 * @return model
	 * @throws CancelledException if monitor is canceled
	 */
	EnsembleModel<Label> trainModel(List<Example<Label>> trainingData, TaskMonitor monitor)
			throws CancelledException {
		LabelFactory lf = new LabelFactory();
		ListDataSource<Label> trainingSource = new ListDataSource<>(trainingData, lf,
			new SimpleDataSourceProvenance(program.getDomainFile().getPathname(), lf));
		trainingSet = new MutableDataset<>(trainingSource);

		//want to select from sqrt(num features) features at each split
		float featureFraction = (float) (1.0f / Math.sqrt(trainingSet.getFeatureMap().size()));

		List<CARTClassificationTrainer> trainers = new ArrayList<>();
		for (int i = 0; i < NUM_TREES; ++i) {
			monitor.checkCancelled();
			//Integer.MAX_VALUE: unlimited depth
			trainers.add(new CARTClassificationTrainer(Integer.MAX_VALUE, featureFraction,
				ThreadLocalRandom.current().nextLong()));
		}

		GThreadPool threadPool = GThreadPool.getSharedThreadPool(RANDOM_FOREST_TRAINING_THREADPOOL);
		monitor.initialize(NUM_TREES);
		monitor.setMessage("Training random forest");

		ConcurrentQBuilder<CARTClassificationTrainer, TreeModel<Label>> builder =
			new ConcurrentQBuilder<>();
		ConcurrentQ<CARTClassificationTrainer, TreeModel<Label>> q =
			builder.setThreadPool(threadPool)
					.setCollectResults(true)
					.setMonitor(monitor)
					.build(new SingleTreeTrainer());
		q.add(trainers);
		EnsembleModel<Label> randomForest = null;
		try {
			long start = System.nanoTime();
			var results = q.waitForResults();
			long end = System.nanoTime();
			Msg.info(this,
				String.format("Training time: %g seconds", (end - start) / NANOSECONDS_PER_SECOND));
			List<Model<Label>> trees = new ArrayList<>();
			for (var r : results) {
				trees.add(r.getResult());
			}
			randomForest = WeightedEnsembleModel.createEnsembleFromExistingModels("rf", trees,
				new VotingCombiner());
		}
		catch (Exception e) {
			monitor.checkCancelled();
			Msg.error(this, "Exception while training model: " + e.getMessage());
		}
		return randomForest;
	}

	/**
	 * Evaluates a model
	 *
	 * @param randomForest model to evaluate
	 * @param testPositive test set of function entries
	 * @param testNegative test set of function interiors
	 * @param errors set to place addresses with classifier errors
	 * @param preBytes number of bytes before entries
	 * @param initialBytes number of bytes before interiors
	 * @param monitor task monitor
	 * @return confusion matrix
	 * @throws CancelledException if monitor is canceled
	 */
	int[] evaluateModel(EnsembleModel<Label> randomForest, AddressSet testPositive,
			AddressSet testNegative, AddressSet errors, int preBytes, int initialBytes,
			TaskMonitor monitor) throws CancelledException {
		GThreadPool threadPool = GThreadPool.getSharedThreadPool(RANDOM_FOREST_TRAINING_THREADPOOL);
		long start = System.nanoTime();
		monitor.setMessage(
			"Evaluating model (step 1 of 2; " + testPositive.getNumAddresses() + " addresses)");
		ConcurrentQBuilder<Address, Boolean> evalBuilder = new ConcurrentQBuilder<>();
		ConcurrentQ<Address, Boolean> evalQ = evalBuilder.setThreadPool(threadPool)
				.setCollectResults(true)
				.setMonitor(monitor)
				.build(new EnsembleEvaluatorCallback(randomForest, program, preBytes, initialBytes,
					params.getIncludeBitFeatures(), RandomForestFunctionFinderPlugin.FUNC_START));
		evalQ.add(testPositive.getAddresses(true));
		int[] confusionMatrix = new int[4];
		try {
			Collection<QResult<Address, Boolean>> results = evalQ.waitForResults();
			updateConfusionMatrix(results, confusionMatrix,
				RandomForestFunctionFinderPlugin.FUNC_START, errors);
		}
		catch (Exception e) {
			monitor.checkCancelled();
			Msg.error(this,
				"Exception while evaluating model on known function starts: " + e.getMessage());
		}
		monitor.setMessage(
			"Evaluating model (step 2 of 2; " + testNegative.getNumAddresses() + " addresses)");
		evalQ = evalBuilder.setThreadPool(threadPool)
				.setCollectResults(true)
				.setMonitor(monitor)
				.build(new EnsembleEvaluatorCallback(randomForest, program, preBytes, initialBytes,
					params.getIncludeBitFeatures(), RandomForestFunctionFinderPlugin.NON_START));

		evalQ.add(testNegative.getAddresses(true));
		try {
			Collection<QResult<Address, Boolean>> results = evalQ.waitForResults();
			updateConfusionMatrix(results, confusionMatrix,
				RandomForestFunctionFinderPlugin.NON_START, errors);
		}
		catch (Exception e) {
			monitor.checkCancelled();
			Msg.error(this,
				"Exception while evaluating model on known function interiors: " + e.getMessage());
		}
		long end = System.nanoTime();
		Msg.info(this,
			String.format("Evaluation time: %g seconds", (end - start) / NANOSECONDS_PER_SECOND));
		return confusionMatrix;
	}

	/**
	 * Updates the confusion matrix
	 * 
	 * @param results results of classifier
	 * @param confusion confusion matrix
	 * @param target correct answer
	 * @param errors set to place addresses with classifier errors
	 * @throws Exception if exception encountered during processing
	 */
	void updateConfusionMatrix(Collection<QResult<Address, Boolean>> results, int[] confusion,
			Label target, AddressSet errors) throws Exception {
		int trueIndex = target.equals(RandomForestFunctionFinderPlugin.FUNC_START) ? TP : TN;
		int falseIndex = target.equals(RandomForestFunctionFinderPlugin.FUNC_START) ? FN : FP;
		for (QResult<Address, Boolean> result : results) {
			Boolean ans = result.getResult();
			if (ans == null) {
				continue;
			}
			if (ans) {
				confusion[trueIndex] += 1;
			}
			else {
				confusion[falseIndex] += 1;
				errors.add(result.getItem());
			}
		}
	}

	private synchronized DatasetView<Label> getBag() {
		return DatasetView.createBootstrapView(trainingSet, trainingSet.size(),
			ThreadLocalRandom.current().nextLong());
	}

	private class SingleTreeTrainer
			implements QCallback<CARTClassificationTrainer, TreeModel<Label>> {

		@Override
		public TreeModel<Label> process(CARTClassificationTrainer trainer, TaskMonitor monitor)
				throws Exception {
			DatasetView<Label> bag = getBag();
			TreeModel<Label> tree = trainer.train(bag);
			monitor.incrementProgress(1);
			return tree;
		}
	}
}
