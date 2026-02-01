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
package ghidra.feature.vt.api;

import java.util.ArrayList;
import java.util.Set;

import generic.lsh.vector.*;

/**
 * Class(es) for constructing a "neighborhood" of functions around a function
 * that we know has a match.  Comparing across neighborhoods provides a large
 * cut-down in both search time and uncertainty when trying to find additional matches.
 */
public abstract class NeighborGenerator {

	public static final int RELATIVE_COMPARES = 25;		// Maximum number of extra compares between "relative" sets
	private double impThreshold;						// Confidence threshold for extending to additional matches
	private LSHVectorFactory vectorFactory;

	public static class NeighborhoodPair {
		public Set<FunctionNode> srcNeighbors;
		public Set<FunctionNode> destNeighbors;
		public boolean isFilledOut = false;
	}

	public NeighborGenerator(LSHVectorFactory vectorFactory, double impThreshold) {
		this.vectorFactory = vectorFactory;
		this.impThreshold = impThreshold;
	}

	/**
	 * Given roots from the source program and the destination program,
	 * generate a neighborhood of functions related to each root.
	 * @param srcRoot is the root from the source program
	 * @param destRoot is the root from the destination program
	 * @return a pair of "neighborhoods" as a set of FunctionNodes
	 */
	public abstract NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot);

	/**
	 * Do the feature vector comparison of every source to every destination and create
	 * new putative matches (associates) if the comparison score exceeds {@link #impThreshold}
	 * @param unmatchedSource is the list of sources
	 * @param unmatchedDest is the list of destinations
	 */
	private void searchForNewMatches(ArrayList<FunctionNode> unmatchedSource,
			ArrayList<FunctionNode> unmatchedDest) {
		VectorCompare veccompare = new VectorCompare();
		for (FunctionNode src : unmatchedSource) {
			LSHVector srcvec = src.getVector();
			for (FunctionNode dst : unmatchedDest) {
				if (src.findEdge(dst) != null) {
					continue;			// This pair has already been compared
				}
				// Feature vector computations
				double similarity = srcvec.compare(dst.getVector(), veccompare);
				double confidence = vectorFactory.calculateSignificance(veccompare);
				if (confidence < impThreshold) {
					continue;
				}
				FunctionPair newPair = new FunctionPair(src, dst, similarity, confidence);
				src.addAssociate(dst, newPair);
				dst.addAssociate(src, newPair);
			}
		}
	}

	/**
	 * If nodes haven't been compared before, compare them and add an associate if it passes threshold
	 * @param pair is the two sets of nodes that we are comparing between
	 * @param maxCompares is the maximum number of comparisons to perform
	 * @return true is comparisons were actually performed
	 */
	protected boolean fillOutPairs(NeighborhoodPair pair, int maxCompares) {
		ArrayList<FunctionNode> unmatchedSource = new ArrayList<FunctionNode>();
		ArrayList<FunctionNode> unmatchedDest = null;

		for (FunctionNode src : pair.srcNeighbors) {
			if (src.isAcceptedMatch()) {
				continue;
			}
			if (src.getVector() == null) {
				continue;
			}
			unmatchedSource.add(src);
		}

		if (unmatchedSource.isEmpty()) {
			return false;
		}
		if (unmatchedSource.size() > maxCompares) {
			return false;
		}
		unmatchedDest = new ArrayList<FunctionNode>();

		for (FunctionNode dst : pair.destNeighbors) {
			if (dst.isAcceptedMatch()) {
				continue;
			}
			if (dst.getVector() == null) {
				continue;
			}
			unmatchedDest.add(dst);
		}
		if (unmatchedDest.isEmpty()) {
			return false;
		}
		if (unmatchedSource.size() * unmatchedDest.size() > maxCompares) {
			return false;
		}

		searchForNewMatches(unmatchedSource, unmatchedDest);
		return true;
	}

	/**
	 * Parents of -root-
	 */
	public static class Parents extends NeighborGenerator {

		public Parents(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			pair.srcNeighbors = srcRoot.getParents();
			pair.destNeighbors = destRoot.getParents();
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}

	/**
	 * Children of -root-
	 */
	public static class Children extends NeighborGenerator {

		public Children(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			pair.srcNeighbors = srcRoot.getChildren();
			pair.destNeighbors = destRoot.getChildren();
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}

	/**
	 * Grand parents of -root-
	 */
	public static class GrandParents extends NeighborGenerator {

		public GrandParents(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			Set<FunctionNode> tempRels = srcRoot.getParents();
			pair.srcNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.srcNeighbors.addAll(rel.getParents());
			}
			pair.srcNeighbors.remove(srcRoot);

			tempRels = destRoot.getParents();
			pair.destNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.destNeighbors.addAll(rel.getParents());
			}
			pair.destNeighbors.remove(destRoot);
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}

	/**
	 *  Grandchildren of -root-
	 */
	public static class GrandChildren extends NeighborGenerator {

		public GrandChildren(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			Set<FunctionNode> tempRels = srcRoot.getChildren();
			pair.srcNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.srcNeighbors.addAll(rel.getChildren());
			}
			pair.srcNeighbors.remove(srcRoot);

			tempRels = destRoot.getChildren();
			pair.destNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.destNeighbors.addAll(rel.getChildren());
			}
			pair.destNeighbors.remove(destRoot);
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}

	/**
	 * Functions that share a parent with -root-
	 */
	public static class Siblings extends NeighborGenerator {

		public Siblings(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			Set<FunctionNode> tempRels = srcRoot.getParents();
			pair.srcNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.srcNeighbors.addAll(rel.getChildren());
			}
			pair.srcNeighbors.remove(srcRoot);

			tempRels = destRoot.getParents();
			pair.destNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.destNeighbors.addAll(rel.getChildren());
			}
			pair.destNeighbors.remove(destRoot);
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}

	/**
	 *  Functions that share a child with -root-
	 */
	public static class Spouses extends NeighborGenerator {

		public Spouses(LSHVectorFactory vectorFactory, double impThreshold) {
			super(vectorFactory, impThreshold);
		}

		@Override
		public NeighborhoodPair generate(FunctionNode srcRoot, FunctionNode destRoot) {
			NeighborhoodPair pair = new NeighborhoodPair();
			Set<FunctionNode> tempRels = srcRoot.getChildren();
			pair.srcNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.srcNeighbors.addAll(rel.getParents());
			}
			pair.srcNeighbors.remove(srcRoot);

			tempRels = destRoot.getChildren();
			pair.destNeighbors = FunctionNode.neigborhoodAllocate();
			for (FunctionNode rel : tempRels) {
				pair.destNeighbors.addAll(rel.getParents());
			}
			pair.destNeighbors.remove(destRoot);
			fillOutPairs(pair, RELATIVE_COMPARES);
			return pair;
		}
	}
}
