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
import java.util.Map.Entry;

import org.tribuo.Feature;
import org.tribuo.Model;
import org.tribuo.classification.Label;
import org.tribuo.common.tree.Node;
import org.tribuo.common.tree.TreeModel;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.impl.ArrayExample;
import org.tribuo.math.la.SparseVector;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

/**
 * Given a potential function start {@code S} and a random forest trained to recognize 
 * function starts, this class is used to find the function starts in the training set
 * most similar to {@code S}.  Here "similar" is defined in terms of proximity in a
 * random forest (i.e., proportion of trees which agree on two feature vectors).
 * Note that {@code S} may or may not be in the training source program.
 */
public class SimilarStartsFinder {

	private RandomForestRowObject modelAndParams;
	private Program trainingSource;
	private Program targetProgram;
	private int preBytes;
	private int initialBytes;
	private boolean includeBitFeatures;
	private Map<Address, List<Node<Label>>> startsToLeafList = new HashMap<>();
	private EnsembleModel<Label> randomForest;

	/**
	 * Creates a {@link SimilarStartsFinder} for the given program and model
	 * @param trainingSource source of training data
	 * @param targetProgram program being searched
	 * @param modelAndParams model and params
	 */
	public SimilarStartsFinder(Program trainingSource, Program targetProgram,
			RandomForestRowObject modelAndParams) {
		this.trainingSource = trainingSource;
		this.targetProgram = targetProgram;
		this.modelAndParams = modelAndParams;
		preBytes = modelAndParams.getNumPreBytes();
		initialBytes = modelAndParams.getNumInitialBytes();
		includeBitFeatures = modelAndParams.getIncludeBitLevelFeatures();
		randomForest = modelAndParams.getRandomForest();
		computeLeafNodeLists();
	}

	/**
	 * Finds the functions starts in the training set that are most similar to {@code potential}
	 * according to the model
	 * @param potential address of potential start
	 * @param numStarts max size of returned list
	 * @return similar starts (in descending order)
	 */
	public List<SimilarStartRowObject> getSimilarFunctionStarts(Address potential, int numStarts) {
		List<Node<Label>> leafNodes = getLeafNodes(potential, targetProgram);
		List<SimilarStartRowObject> neighbors = new ArrayList<>(startsToLeafList.size());
		for (Entry<Address, List<Node<Label>>> entry : startsToLeafList.entrySet()) {
			Address start = entry.getKey();
			List<Node<Label>> leafList = entry.getValue();
			int matches = 0;
			for (int i = 0; i < randomForest.getNumModels(); ++i) {
				if (leafNodes.get(i).equals(leafList.get(i))) {
					matches++;
				}
			}
			neighbors.add(new SimilarStartRowObject(start, matches));
		}
		Collections.sort(neighbors,
			(x, y) -> Integer.compare(y.numAgreements(), x.numAgreements()));
		List<SimilarStartRowObject> closeNeighbors =
			neighbors.subList(0, Math.min(numStarts, neighbors.size()));
		return closeNeighbors;
	}

	/**
	 * For each function start in the training set and tree in the random forest,
	 * run the corresponding feature vector down the tree and record the leaf node
	 * reached.
	 */
	private void computeLeafNodeLists() {
		AddressSet knownStarts = modelAndParams.getTrainingPositives();
		AddressIterator addrIter = knownStarts.getAddresses(true);
		while (addrIter.hasNext()) {
			Address start = addrIter.next();
			List<Node<Label>> nodeList = getLeafNodes(start, trainingSource);
			startsToLeafList.put(start, nodeList);
		}
	}

	/**
	 * Creates a feature vector for {@code addr}, runs it down each tree in the forest,
	 * and records the leaf node reached.
	 * @param addr (potential) function start
	 * @param program program containing {@code addr}
	 * @return list of leaf nodes
	 */
	List<Node<Label>> getLeafNodes(Address addr, Program program) {
		List<Node<Label>> leafNodes = new ArrayList<>(randomForest.getNumModels());
		List<Feature> potentialFeatureVector = ModelTrainingUtils.getFeatureVector(program, addr,
			preBytes, initialBytes, includeBitFeatures);
		ArrayExample<Label> example =
			new ArrayExample<>(RandomForestFunctionFinderPlugin.FUNC_START, potentialFeatureVector);
		SparseVector vec =
			SparseVector.createSparseVector(example, randomForest.getFeatureIDMap(), false);
		for (Model<Label> member : randomForest.getModels()) {
			TreeModel<Label> tree = (TreeModel<Label>) member;
			Node<Label> node = tree.getRoot();
			while (!node.isLeaf()) {
				node = node.getNextNode(vec);
			}
			leafNodes.add(node);
		}
		return leafNodes;
	}

}
