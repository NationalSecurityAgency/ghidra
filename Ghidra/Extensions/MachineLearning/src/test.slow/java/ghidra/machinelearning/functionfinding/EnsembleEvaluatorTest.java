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

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class EnsembleEvaluatorTest extends AbstractProgramBasedTest {

	private ProgramBuilder builder;

	@Override
	protected Program getProgram() throws Exception {
		builder = new ClassicSampleX86ProgramBuilder();
		ProgramDB p = builder.getProgram();
		return p;
	}

	@Test
	public void basicEvaluatorTest() throws Exception {
		initialize();
		DummyClassifierTrainer dummyStartTrainer = DummyClassifierTrainer
				.createConstantTrainer(RandomForestFunctionFinderPlugin.FUNC_START.getLabel());
		DummyClassifierTrainer dummyNonStartTrainer = DummyClassifierTrainer
				.createConstantTrainer(RandomForestFunctionFinderPlugin.NON_START.getLabel());
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
			new ListDataSource<Label>(trainingData, lf, new SimpleDataSourceProvenance("test", lf));
		MutableDataset<Label> trainingSet = new MutableDataset<>(trainingSource);

		//10 models, encounters 5 yes votes first
		List<Model<Label>> models = new ArrayList<>();
		for (int i = 0; i < 10; i++) {
			models.add(dummyStartTrainer.train(trainingSet));
			models.add(dummyNonStartTrainer.train(trainingSet));
		}

		EnsembleModel<Label> ensemble = WeightedEnsembleModel
				.createEnsembleFromExistingModels("test", models, new VotingCombiner());
		EnsembleEvaluatorCallback testEval = new EnsembleEvaluatorCallback(ensemble, program, 1, 1,
			true, RandomForestFunctionFinderPlugin.FUNC_START);
		Boolean res = testEval.process(testStart, TaskMonitor.DUMMY);
		assertTrue(res);

		//10 models, encounters 5 no votes first
		//there are also 5 voting yes, ties should go to yes
		models.clear();
		for (int i = 0; i < 10; ++i) {
			models.add(dummyNonStartTrainer.train(trainingSet));
			models.add(dummyStartTrainer.train(trainingSet));
		}
		ensemble = WeightedEnsembleModel.createEnsembleFromExistingModels("test", models,
			new VotingCombiner());
		testEval = new EnsembleEvaluatorCallback(ensemble, program, 1, 1, true,
			RandomForestFunctionFinderPlugin.FUNC_START);
		res = testEval.process(testStart, TaskMonitor.DUMMY);
		assertTrue(res);

		//10 models, encounters 4 yes votes then 6 no votes
		models.clear();
		for (int i = 0; i < 4; ++i) {
			models.add(dummyStartTrainer.train(trainingSet));
		}
		for (int i = 0; i < 6; ++i) {
			models.add(dummyNonStartTrainer.train(trainingSet));
		}
		ensemble = WeightedEnsembleModel.createEnsembleFromExistingModels("test", models,
			new VotingCombiner());
		testEval = new EnsembleEvaluatorCallback(ensemble, program, 1, 1, true,
			RandomForestFunctionFinderPlugin.FUNC_START);
		res = testEval.process(testStart, TaskMonitor.DUMMY);
		assertFalse(res);

		//11 models, encounters 5 no votes first then 6 yes votes
		models.clear();
		for (int i = 0; i < 10; i++) {
			models.add(dummyNonStartTrainer.train(trainingSet));
			models.add(dummyStartTrainer.train(trainingSet));
		}
		models.add(dummyStartTrainer.train(trainingSet));
		ensemble = WeightedEnsembleModel.createEnsembleFromExistingModels("test", models,
			new VotingCombiner());
		testEval = new EnsembleEvaluatorCallback(ensemble, program, 1, 1, true,
			RandomForestFunctionFinderPlugin.FUNC_START);
		res = testEval.process(testStart, TaskMonitor.DUMMY);
		assertTrue(res);

		//11 models, encounters 5 yes votes first then 6 no votes
		models.clear();
		for (int i = 0; i < 5; ++i) {
			models.add(dummyStartTrainer.train(trainingSet));
		}
		for (int i = 0; i < 6; ++i) {
			models.add(dummyNonStartTrainer.train(trainingSet));
		}
		ensemble = WeightedEnsembleModel.createEnsembleFromExistingModels("test", models,
			new VotingCombiner());
		testEval = new EnsembleEvaluatorCallback(ensemble, program, 1, 1, true,
			RandomForestFunctionFinderPlugin.FUNC_START);
		res = testEval.process(testStart, TaskMonitor.DUMMY);
		assertFalse(res);
	}

}
