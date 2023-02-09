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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;
import org.tribuo.*;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.classification.baseline.DummyClassifierTrainer;
import org.tribuo.classification.ensemble.VotingCombiner;
import org.tribuo.datasource.ListDataSource;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.ensemble.WeightedEnsembleModel;
import org.tribuo.provenance.SimpleDataSourceProvenance;

import generic.concurrent.QResult;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class RandomForestTrainingTaskTest extends AbstractProgramBasedTest {

	private ProgramBuilder builder;
	private FunctionStartRFParams params;

	@Before
	public void setup() throws Exception {
		initialize();
	}

	@Override
	protected Program getProgram() throws Exception {
		builder = new ClassicSampleX86ProgramBuilder();
		ProgramDB p = builder.getProgram();
		return p;
	}

	@Test
	public void testUpdateConfusionMatrix() throws Exception {
		//test with one true positive, one false positive, one true negative, and one false negative

		Address truePositive = program.getSymbolTable().getSymbols("entry").next().getAddress();
		Address falsePositive = truePositive.add(1);
		Address falseNegative = falsePositive.add(1);
		Address trueNegative = falseNegative.add(1);
		int[] confusionMatrix = new int[RandomForestTrainingTask.CONFUSION_MATRIX_SIZE];
		AddressSet errors = new AddressSet();
		List<QResult<Address, Boolean>> examples = new ArrayList<>();
		examples.add(new QResult<>(truePositive, CompletableFuture.completedFuture(true)));
		examples.add(new QResult<>(falsePositive, CompletableFuture.completedFuture(false)));
		//don't need any of the fields of RandomForestTrainingTask for this test
		RandomForestTrainingTask task = new RandomForestTrainingTask(program, null, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		task.updateConfusionMatrix(examples, confusionMatrix,
			RandomForestFunctionFinderPlugin.FUNC_START, errors);
		assertEquals(1, errors.getNumAddresses());
		assertTrue(errors.contains(falsePositive));
		errors.clear();
		examples.clear();
		examples.add(new QResult<>(falseNegative, CompletableFuture.completedFuture(false)));
		examples.add(new QResult<>(trueNegative, CompletableFuture.completedFuture(true)));
		task.updateConfusionMatrix(examples, confusionMatrix,
			RandomForestFunctionFinderPlugin.NON_START, errors);
		assertEquals(1, errors.getNumAddresses());
		assertTrue(errors.contains(falseNegative));
		assertEquals(1, confusionMatrix[RandomForestTrainingTask.TP]);
		assertEquals(1, confusionMatrix[RandomForestTrainingTask.FP]);
		assertEquals(1, confusionMatrix[RandomForestTrainingTask.TN]);
		assertEquals(1, confusionMatrix[RandomForestTrainingTask.FN]);
	}

	@Test
	public void testEvaluateModel() throws CancelledException {
		DummyClassifierTrainer dummyStartTrainer = DummyClassifierTrainer
				.createConstantTrainer(RandomForestFunctionFinderPlugin.FUNC_START.getLabel());
		List<Example<Label>> trainingData = new ArrayList<>();
		AddressSet starts = new AddressSet();
		AddressSet nonStarts = new AddressSet();

		//just need an address with 1 defined preByte and 1 defined byte
		Address testStart = program.getSymbolTable().getSymbols("entry").next().getAddress().add(1);
		Address testNonStart = testStart.add(1);
		starts.add(testStart);
		nonStarts.add(testNonStart);
		trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program, starts,
			RandomForestFunctionFinderPlugin.FUNC_START, 1, 1, true, TaskMonitor.DUMMY));
		trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program, nonStarts,
			RandomForestFunctionFinderPlugin.NON_START, 1, 1, true, TaskMonitor.DUMMY));
		LabelFactory lf = new LabelFactory();
		ListDataSource<Label> trainingSource =
			new ListDataSource<>(trainingData, lf, new SimpleDataSourceProvenance("test", lf));
		MutableDataset<Label> trainingSet = new MutableDataset<>(trainingSource);

		//create ensemble with two models which always report FUNC_START  
		List<Model<Label>> models = new ArrayList<>();
		models.add(dummyStartTrainer.train(trainingSet));
		models.add(dummyStartTrainer.train(trainingSet));
		WeightedEnsembleModel<Label> ensemble = WeightedEnsembleModel
				.createEnsembleFromExistingModels("test", models, new VotingCombiner());
		params = new FunctionStartRFParams(program);
		params.setIncludeBitFeatures(true);
		AddressSet errors = new AddressSet();
		RandomForestTrainingTask task = new RandomForestTrainingTask(program, params, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		int[] confusion =
			task.evaluateModel(ensemble, starts, nonStarts, errors, 1, 1, TaskMonitor.DUMMY);
		assertEquals(1, errors.getNumAddresses());
		assertTrue(errors.contains(testNonStart));
		assertEquals(1, confusion[RandomForestTrainingTask.TP]);
		assertEquals(1, confusion[RandomForestTrainingTask.FP]);
		assertEquals(0, confusion[RandomForestTrainingTask.TN]);
		assertEquals(0, confusion[RandomForestTrainingTask.FN]);

		//create ensemble with two models which always report NON_START
		DummyClassifierTrainer dummyNonStartTrainer = DummyClassifierTrainer
				.createConstantTrainer(RandomForestFunctionFinderPlugin.NON_START.getLabel());
		models = new ArrayList<>();
		models.add(dummyNonStartTrainer.train(trainingSet));
		models.add(dummyNonStartTrainer.train(trainingSet));
		ensemble = WeightedEnsembleModel.createEnsembleFromExistingModels("test", models,
			new VotingCombiner());
		errors = new AddressSet();
		confusion =
			task.evaluateModel(ensemble, starts, nonStarts, errors, 1, 1, TaskMonitor.DUMMY);
		assertEquals(1, errors.getNumAddresses());
		assertTrue(errors.contains(testStart));
		assertEquals(0, confusion[RandomForestTrainingTask.TP]);
		assertEquals(0, confusion[RandomForestTrainingTask.FP]);
		assertEquals(1, confusion[RandomForestTrainingTask.TN]);
		assertEquals(1, confusion[RandomForestTrainingTask.FN]);
	}

	@Test
	public void testTrainModel() throws CancelledException {
		//train an ensemble on a trivial data set and verify that it contains the correct number
		//of models
		List<Example<Label>> trainingData = new ArrayList<>();
		AddressSet starts = new AddressSet();
		AddressSet nonStarts = new AddressSet();
		//just need an address with 1 defined preByte and 1 defined byte
		Address testStart = program.getSymbolTable().getSymbols("entry").next().getAddress().add(1);
		Address testNonStart = testStart.add(1);
		starts.add(testStart);
		nonStarts.add(testNonStart);
		trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program, starts,
			RandomForestFunctionFinderPlugin.FUNC_START, 1, 1, true, TaskMonitor.DUMMY));
		trainingData.addAll(ModelTrainingUtils.getVectorsFromAddresses(program, nonStarts,
			RandomForestFunctionFinderPlugin.NON_START, 1, 1, true, TaskMonitor.DUMMY));
		//don't need any of the fields of RandomForestTrainingTask for this test
		RandomForestTrainingTask task = new RandomForestTrainingTask(program, null, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		EnsembleModel<Label> ensemble = task.trainModel(trainingData, TaskMonitor.DUMMY);
		assertEquals(RandomForestTrainingTask.NUM_TREES, ensemble.getNumModels());
	}

	@Test
	public void testSimilarStartsFinder() {
		params = new FunctionStartRFParams(program);
		List<Integer> testList = new ArrayList<>();
		testList.add(5);
		params.setFactors(testList);
		params.setIncludeBitFeatures(true);
		params.setIncludePrecedingAndFollowing(true);
		params.setInitialBytes(testList);
		params.setMaxStarts(100);
		params.setMinFuncSize(16);
		params.setPreBytes(testList);
		List<RandomForestRowObject> rows = new ArrayList<>();
		RandomForestTrainingTask task =
			new RandomForestTrainingTask(program, params, x -> rows.add(x), 100);
		TaskLauncher.launchModal("test", task);
		assertEquals(1, rows.size());
		SimilarStartsFinder finder = new SimilarStartsFinder(program, program, rows.get(0));
		Address entryAddr = program.getSymbolTable().getSymbols("entry").next().getAddress();
		List<SimilarStartRowObject> res = finder.getSimilarFunctionStarts(entryAddr, 7);
		//just verify that the number of elements is correct, each element is a function start,
		//and that the list is in descending order.
		assertEquals(7, res.size());
		res.forEach(
			r -> assertTrue(program.getFunctionManager().getFunctionAt(r.funcStart()) != null));
		int currentNum = res.get(0).numAgreements();
		for (int i = 1; i < 7; ++i) {
			assertTrue(currentNum >= res.get(i).numAgreements());
			currentNum = res.get(i).numAgreements();
		}
	}

	@Test
	public void getTrainingAndTestDataBasicTest() throws CancelledException {
		params = new FunctionStartRFParams(program);
		params.setMaxStarts(5);
		Address begin = program.getSymbolTable().getSymbols("entry").next().getAddress();
		AddressSet entries = new AddressSet();
		for (int i = 0; i < 10; ++i) {
			entries.add(begin.add(i));
		}
		AddressSet interiors = new AddressSet();
		for (int i = 10; i < 25; ++i) {
			interiors.add(begin.add(i));
		}
		AddressSet definedData = new AddressSet();
		for (int i = 25; i < 30; ++i) {
			definedData.add(begin.add(i));
		}
		RandomForestTrainingTask task = new RandomForestTrainingTask(program, params, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		TrainingAndTestData data =
			task.getTrainingAndTestData(entries, interiors, definedData, 2, TaskMonitor.DUMMY);
		//5 function starts chosen from 10 possible
		assertEquals(5, data.getTrainingPositive().getNumAddresses());
		//5*2 interiors chosen from 15 possible
		assertEquals(10, data.getTrainingNegative().getNumAddresses());
		//5 function starts were not chosen
		assertEquals(5, data.getTestPositive().getNumAddresses());
		//5 interiors were not chosen + 5 defined data
		assertEquals(10, data.getTestNegative().getNumAddresses());
		assertTrue(data.getTestPositive()
				.union(data.getTestNegative())
				.intersect(data.getTrainingNegative().union(data.getTrainingPositive()))
				.isEmpty());
		assertTrue(data.getTestPositive().intersect(data.getTestNegative()).isEmpty());
		assertTrue(data.getTrainingPositive().intersect(data.getTrainingNegative()).isEmpty());
		assertTrue(entries.contains(data.getTestPositive()));
		assertTrue(entries.contains(data.getTrainingPositive()));
		assertTrue(interiors.contains(data.getTrainingNegative()));
		assertTrue(interiors.contains(data.getTestNegative().subtract(definedData)));
		assertTrue(data.getTestNegative().contains(definedData));
	}

	//FUN_010059a3 is legit

	//
	// 100641f                      00
	// 1006420 55                   PUSH EBP        <- entry 
	// 1006421 8b ec                MOV EBP, ESP
	// 
	// 1006423 6a ff                PUSH -0x1
	// 1006425 66 88 18 00 01       PUSH DAT_01001888
	// 100642a 68 d0 65 00 01       PUSH DAT_010065d0 
	// 
	// 100642f 64 a1 00 00 00 00    MOV EAX, FS:[0x0]
	// 1006435 50                   PUSH EAX
	// 1006436 64 89 25 00 00 00 00 MOV dword ptr FS:[0x0],ESP
	//
	@Test
	public void getTrainingAndTestDataDeluxeTest() throws CancelledException {
		params = new FunctionStartRFParams(program);
		params.setMaxStarts(2);
		params.setIncludePrecedingAndFollowing(true);
		Address begin = program.getSymbolTable().getSymbols("entry").next().getAddress();

		//create 3 starts, spaced out because we want to include the previous and following 
		AddressSet entries = new AddressSet();
		entries.add(begin);
		entries.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1006425));
		entries.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1006435));

		AddressSet interiors = new AddressSet();
		for (int i = 0x20; i < 0x25; ++i) {
			interiors.add(begin.add(i));
		}
		AddressSet definedData = new AddressSet();
		for (int i = 0x30; i < 0x35; ++i) {
			definedData.add(begin.add(i));
		}

		RandomForestTrainingTask task = new RandomForestTrainingTask(program, params, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		Address otherFuncEntry =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10059a3);
		Function func = program.getFunctionManager().getFunctionAt(otherFuncEntry);
		task.setAdditional(
			new ProgramSelection(func.getBody().getMinAddress(), func.getBody().getMaxAddress()));

		TrainingAndTestData data =
			task.getTrainingAndTestData(entries, interiors, definedData, 2, TaskMonitor.DUMMY);

		//2 function starts chosen from 3 possible
		//plus the entry of the function at 0x1005913 which was added explicitly
		assertEquals(3, data.getTrainingPositive().getNumAddresses());
		assertTrue(data.getTrainingPositive().contains(otherFuncEntry));

		//2*2 interiors chosen from 5 possible
		//2*2 plus preceding and following for two functions selected at random
		//plus size of interior of function at 0x10059a3
		assertEquals(4 + 4 + func.getBody().getNumAddresses() - 1,
			data.getTrainingNegative().getNumAddresses());
		//1 function start was not chosen
		assertEquals(1, data.getTestPositive().getNumAddresses());
		//1 interior was not chosen + (preceding and following for unchosen entry) +  5 defined data
		assertEquals(8, data.getTestNegative().getNumAddresses());
		assertTrue(data.getTestPositive()
				.union(data.getTestNegative())
				.intersect(data.getTrainingNegative().union(data.getTrainingPositive()))
				.isEmpty());
		assertTrue(data.getTestPositive().intersect(data.getTestNegative()).isEmpty());
		assertTrue(data.getTrainingPositive().intersect(data.getTrainingNegative()).isEmpty());
		assertTrue(entries.contains(data.getTestPositive()));
		assertFalse(entries.contains(data.getTrainingPositive()));
		AddressSet deluxeEntries = entries.union(new AddressSet(otherFuncEntry));
		assertTrue(deluxeEntries.contains(data.getTrainingPositive()));

		int numContained = 0;
		Address entry_1006420 = begin;
		Address entry_1006425 = begin.add(5l);
		Address entry_1006435 = begin.add(0x15l);

		if (data.getTrainingPositive().contains(entry_1006420)) {
			numContained += 1;
			assertTrue(data.getTrainingNegative().contains(entry_1006420.subtract(1l)));
			assertTrue(data.getTrainingNegative().contains(entry_1006420.add(1l)));
		}

		if (data.getTrainingPositive().contains(entry_1006425)) {
			numContained += 1;
			assertTrue(data.getTrainingNegative().contains(entry_1006425.subtract(2l)));
			assertTrue(data.getTrainingNegative().contains(entry_1006425.add(5l)));
		}

		if (data.getTrainingPositive().contains(entry_1006435)) {
			numContained += 1;
			assertTrue(data.getTrainingNegative().contains(entry_1006435.subtract(6l)));
			assertTrue(data.getTrainingNegative().contains(entry_1006435.add(1l)));
		}

		assertEquals(2, numContained);

		assertTrue(data.getTestNegative().contains(interiors.subtract(data.getTrainingNegative())));
		assertTrue(data.getTestNegative().contains(definedData));
	}

	@Test
	public void testExhaustingFunctionInteriors() throws CancelledException {
		params = new FunctionStartRFParams(program);
		params.setMaxStarts(5);
		int tooBig = 10;
		Address begin = program.getSymbolTable().getSymbols("entry").next().getAddress();
		AddressSet entries = new AddressSet();
		for (int i = 0; i < 10; ++i) {
			entries.add(begin.add(i));
		}
		AddressSet interiors = new AddressSet();
		for (int i = 10; i < 25; ++i) {
			interiors.add(begin.add(i));
		}
		AddressSet definedData = new AddressSet();
		for (int i = 25; i < 30; ++i) {
			definedData.add(begin.add(i));
		}
		RandomForestTrainingTask task = new RandomForestTrainingTask(program, params, null,
			RandomForestFunctionFinderPlugin.TEST_SET_MAX_SIZE_DEFAULT);
		TrainingAndTestData data =
			task.getTrainingAndTestData(entries, interiors, definedData, tooBig, TaskMonitor.DUMMY);
		assertTrue(data.getTrainingPositive().getNumAddresses() == 5);
		assertTrue(data.getTestPositive().getNumAddresses() == 5);
		assertTrue(data.getTestPositive().union(data.getTrainingPositive()).equals(entries));
		assertTrue(data.getTrainingNegative().equals(interiors));
		assertTrue(data.getTestNegative().equals(definedData));
	}

}
