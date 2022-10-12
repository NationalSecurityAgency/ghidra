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
import java.io.IOException;
import java.nio.file.Paths;

import org.tribuo.*;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.classification.dtree.CARTClassificationTrainer;
import org.tribuo.classification.ensemble.VotingCombiner;
import org.tribuo.classification.evaluation.LabelEvaluation;
import org.tribuo.classification.evaluation.LabelEvaluator;
import org.tribuo.common.tree.RandomForestTrainer;
import org.tribuo.data.csv.CSVLoader;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.evaluation.TrainTestSplitter;

public class ExampleTribuoRunner {

	public static void main(String args[]) throws IOException {

		var irisHeaders =
			new String[] { "sepalLength", "sepalWidth", "petalLength", "petalWidth", "species" };
		DataSource<Label> irisData = new CSVLoader<>(new LabelFactory()).loadDataSource(
			Paths.get("/home/jmworth/ml/bezdekIris.data"), /* Output column   */ irisHeaders[4],
			/* Column headers  */ irisHeaders);

		// Split iris data into training set (70%) and test set (30%)
		var splitIrisData =
			new TrainTestSplitter<>(irisData, /* Train fraction */ 0.7, /* RNG seed */ 1L);
		var trainData = new MutableDataset<>(splitIrisData.getTrain());
		var testData = new MutableDataset<>(splitIrisData.getTest());

		// We can train a decision tree
		var cartTrainer = new CARTClassificationTrainer(100, (float) 0.2, 0);

		var decisionTree = cartTrainer.train(trainData);

		//Model<Label> tree = cartTrainer.train(trainData);

		var trainer = new RandomForestTrainer<>(cartTrainer,                 // trainer - the tree trainer
			new VotingCombiner(),         // combiner - the combining function for the ensemble
			10                               // numMembers - the number of ensemble members to train
		);

		EnsembleModel<Label> tree = trainer.train(trainData);

		// Finally we make predictions on unseen data
		// Each prediction is a map from the output names (i.e. the labels) to the scores/probabilities
		Prediction<Label> prediction = tree.predict(testData.getExample(0));

		// Or we can evaluate the full test dataset, calculating the accuracy, F1 etc.
		LabelEvaluation evaluation = new LabelEvaluator().evaluate(tree, testData);
		// we can inspect the evaluation manually
		double acc = evaluation.accuracy();
		// which returns 0.978
		// or print a formatted evaluation string
		System.out.println(evaluation.toString());
	}

}
