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

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;

import generic.concurrent.*;
import generic.lsh.LSHMemoryModel;
import generic.lsh.vector.LSHVectorFactory;
import generic.lsh.vector.VectorCompare;
import ghidra.feature.vt.api.NeighborGenerator.NeighborhoodPair;
import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for running the BSim function matching algorithm, which happens in stages:
 *   1) Construct BSimProgramCorrelatorMatching with prepopulated FunctionNodeContainers, one for source and destination programs
 *   2) Call discoverPotentialMatches to do raw vector comparisons among source and destination
 *   3) Call generateSeeds to select an initial set of high confidence matches
 *   4) Call doMatching to extend the seed set into a full list of matches
 */
public class BSimProgramCorrelatorMatching {

	private SortedSet<PotentialPair> implications;	// Current potential matches sorted by score
	private FunctionNodeContainer sourceNodes;		// Nodes (functions) associated with the source program
	private FunctionNodeContainer destNodes;		// Nodes associated with the destination program
	private LSHVectorFactory vectorFactory;			// Factory for generating weighted vectors for comparing nodes
	private LinkedList<FunctionPair> matches;		// The list of final matches
	private Set<FunctionPair> seeds;				// Initial set of match pairs used for growing out full set of matches
	private List<FunctionPair> discoveredMatches;	// Raw of set of pairs of similar functions
	private double confThreshold;					// Initial confidence threshold for selecting seed matches
	private double impThreshold;					// Confidence threshold for extending to additional matches
	private double potentialSimThreshold;			// Similarity threshold used when discovering potential matches
	private LSHMemoryModel memoryModel;				// The memory model to use when binning vectors
	private boolean useNamespaceNeighbors;			// True if namespace information is used in matching

	/**
	 * This class is used to lookup potential matches in the {@link BinningSystem} and do
	 * secondary testing by computing similarities of feature vectors.
	 * Searching happens in parallel.
	 */
	private class MatchingCallback implements QCallback<FunctionNode, List<FunctionPair>> {

		private BinningSystem sourceBinning;
		private double simThreshold;

		MatchingCallback(BinningSystem sourceBinning, double simThreshold) {
			this.sourceBinning = sourceBinning;
			this.simThreshold = simThreshold;
		}

		@Override
		public List<FunctionPair> process(FunctionNode queryNode, TaskMonitor monitor)
				throws Exception {
			monitor.checkCancelled();

			if ((queryNode == null) || (queryNode.getVector() == null)) {
				monitor.incrementProgress(1);
				return null;
			}

			List<FunctionPair> associates = new LinkedList<FunctionPair>();
			findSimilarNodes(associates, queryNode, monitor);
			monitor.incrementProgress(1);
			return associates;
		}

		/**
		 * Lookup potential matches for -queryNode- in the binning system,
		 * and perform secondary testing to see if we have a full (potential) match.
		 * Pairs that exceed the threshold are added to the -results- list
		 * @param results is the list of FunctionPairs passing the similarity test
		 * @param queryNode is the base FunctionNode to compare
		 * @param monitor is the TaskMonitor
		 * @throws CancelledException if the user cancels the correlation
		 */
		private void findSimilarNodes(List<FunctionPair> results, FunctionNode queryNode,
				TaskMonitor monitor) throws CancelledException {

			//Set up for matching via feature vector comparison.
			Set<FunctionNode> neighbors = sourceBinning.lookup(queryNode);
			VectorCompare veccompare = new VectorCompare();

			//Check each neighbor from the system of binnings to see if they pass a round of matching.
			for (FunctionNode neighbor : neighbors) {
				monitor.checkCancelled();

				//Feature vector computations
				double similarity = neighbor.getVector().compare(queryNode.getVector(), veccompare);
				if (similarity < simThreshold) {
					continue;
				}
				double confidence = vectorFactory.calculateSignificance(veccompare);

				//Create FunctionPair (bridge in the graph from source to dest)
				FunctionPair newPair =
					new FunctionPair(neighbor, queryNode, similarity, confidence);

				results.add(newPair);
			}
		}
	}

	/**
	 * @param sourceNodes is the container for source functions
	 * @param destNodes is the container for destination functions
	 * @param vFactory is the factory for building feature vectors during analysis
	 * @param conf is the initial confidence threshold for seeds
	 * @param imp is the follow-on confidence for extending to additional matches
	 * @param sim is the similarity threshold used when discovering matches
	 * @param useNamespace true if namespace info is used to find additional matches
	 * @param model is the memory model to use when discovering seed matches
	 */
	public BSimProgramCorrelatorMatching(FunctionNodeContainer sourceNodes,
			FunctionNodeContainer destNodes, LSHVectorFactory vFactory, double conf, double imp,
			double sim, boolean useNamespace, LSHMemoryModel model) {
		this.sourceNodes = sourceNodes;
		this.destNodes = destNodes;
		this.vectorFactory = vFactory;
		confThreshold = conf;
		impThreshold = imp;
		potentialSimThreshold = sim;
		useNamespaceNeighbors = useNamespace;
		memoryModel = model;
		implications = new TreeSet<PotentialPair>();
	}

	/**
	 * Formally accept a FunctionPair as a match. Update bookkeeping to indicate the match.
	 * @param bridge is the pair to accept as a match
	 */
	private void acceptMatch(FunctionPair bridge) {
		FunctionNode sourceNode = bridge.getSourceNode();
		FunctionNode destNode = bridge.getDestNode();
		sourceNode.setAcceptedMatch(true);
		destNode.setAcceptedMatch(true);
		matches.add(bridge);

		// Given the pair, remove the source and destination as a potential matches from any other node.
		Iterator<Entry<FunctionNode, FunctionPair>> iter = sourceNode.getAssociateIterator();
		while (iter.hasNext()) {
			iter.next().getKey().removeAssociate(sourceNode);
		}
		iter = destNode.getAssociateIterator();
		while (iter.hasNext()) {
			iter.next().getKey().removeAssociate(destNode);
		}
		sourceNode.clearAssociates();	// Clear old potential matches
		destNode.clearAssociates();
	}

	/**
	 * Do vector comparisons between the source and destination FunctionNodes.
	 * Anything discovered that exceeds {@link #potentialSimThreshold} is placed into {@link #discoveredMatches}
	 * A {@link BinningSystem} is built, then individual FunctionNodes are searched in parallel.
	 * @param monitor is the TaskMonitor
	 * @throws Exception for user cancellation or other problems
	 */
	public void discoverPotentialMatches(TaskMonitor monitor) throws Exception {

		BinningSystem binning = new BinningSystem(memoryModel);
		monitor.setMessage("Binning source functions...");
		monitor.initialize(sourceNodes.size());
		binning.add(sourceNodes.iterator(), monitor);

		monitor.setMessage("Zealously over-pairing matches...");
		monitor.initialize(destNodes.size());

		//
		// Queue setup
		//
		GThreadPool pool = GThreadPool.getPrivateThreadPool("BSimProgramCorrelatorMatching");
		QCallback<FunctionNode, List<FunctionPair>> callback =
			new MatchingCallback(binning, potentialSimThreshold);

		// @formatter:off
		ConcurrentQ<FunctionNode, List<FunctionPair>> queue = 
			new ConcurrentQBuilder<FunctionNode, List<FunctionPair>>()					
				.setThreadPool(pool)
				.setCollectResults(true)
				.setMonitor(monitor)
				.build(callback);
		// @formatter:on

		//
		// Submit and wait for results
		//
		queue.add(destNodes.iterator());

		Collection<QResult<FunctionNode, List<FunctionPair>>> results;
		try {
			results = queue.waitForResults();
		}
		finally {
			queue.dispose();
		}

		discoveredMatches = new LinkedList<FunctionPair>();
		for (QResult<FunctionNode, List<FunctionPair>> result : results) {
			monitor.checkCancelled();
			List<FunctionPair> pieces = result.getResult();
			if (pieces == null) {
				continue;
			}
			for (FunctionPair bridge : pieces) {
				monitor.checkCancelled();
				if (bridge != null) {
					FunctionNode sourceNode = bridge.getSourceNode();
					FunctionNode destNode = bridge.getDestNode();
					sourceNode.addAssociate(destNode, bridge);
					destNode.addAssociate(sourceNode, bridge);
					discoveredMatches.add(bridge);
				}
			}
		}
	}

	/**
	 * Find the last index in the (sorted) list where the confidence is >= threshold
	 * @param pairs is the sorted list
	 * @param threshold to find
	 * @return the index
	 */
	private static int findIndexMatchingThreshold(ArrayList<FunctionPair> pairs, double threshold) {
		int min = 0;
		int max = pairs.size() - 1;
		while (min < max) {
			int mid = (min + max + 1) / 2;			// Guarantee if min != max,  then mid != min
			FunctionPair pair = pairs.get(mid);
			if (pair.getConfResult() < threshold) {
				max = mid - 1;
			}
			else {
				min = mid;
			}
		}
		return min;
	}

	/**
	 * Choose seed FunctionNode pairs with the highest confidence from among {@link #discoveredMatches}
	 * making sure there are no conflicts, (a FunctionNode that is involved in multiple matches).
	 * Selection happens in rounds.  During a round:
	 *   a) "Accept" all pairs for which there is no immediate conflict
	 *   b) If a pair has conflicts, throw it out if either:
	 *          1) The number of children is different between source and dest (difference > threshold) 
	 *          2) The function length is different between source and dest (difference > threshold)
	 *          
	 * Between rounds the "accepted" pairs and the "thrown out" pairs may remove conflicts from the
	 * remaining pairs.  Each round the threshold for throwing out a conflict is tightened.
	 * 
	 * The process terminates when no new pairs are accepted during a round.
	 * The accepted pairs are sorted by confidence, and those exceeding {@link #confThreshold} become
	 * the final seed set.
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the correlation
	 */
	private void chooseSeeds(TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Generating seeds...");
		ArrayList<FunctionPair> finalPairs = new ArrayList<FunctionPair>();
		HashSet<FunctionNode> matchedSource = new HashSet<FunctionNode>();	// Source functions that are matched
		HashSet<FunctionNode> matchedDest = new HashSet<FunctionNode>();	// Dest functions that are matched
		MultiValuedMap<FunctionNode, FunctionPair> sourceHoldOn =
			new HashSetValuedHashMap<FunctionNode, FunctionPair>();			// Conflicting source functions held for next round
		MultiValuedMap<FunctionNode, FunctionPair> destHoldOn =
			new HashSetValuedHashMap<FunctionNode, FunctionPair>();			// Conflicting dest functions held for next round
		MultiValuedMap<FunctionNode, FunctionPair> sourceFormatted =
			new HashSetValuedHashMap<FunctionNode, FunctionPair>();			// Current set of potential pairs, indexed by source
		MultiValuedMap<FunctionNode, FunctionPair> destFormatted =
			new HashSetValuedHashMap<FunctionNode, FunctionPair>();			// Current set of potential pairs, indexed by dest

		for (FunctionPair pair : discoveredMatches) {					// Copy putative matches into the "current" set of potential pairs
			sourceFormatted.put(pair.getSourceNode(), pair);
			destFormatted.put(pair.getDestNode(), pair);
		}
		discoveredMatches = null;			// The raw match list is no longer needed beyond this point

		int keepLen = sourceFormatted.size();
		if (keepLen == 0) {
			return;
		}

		boolean changed = true;
		double ratioThresh = .5;	// Initial threshold for throwing out pairs.  Counts can differ by a factor of 2 to 1.
		while (changed) {			// Keep going until no change (no new pairs)
			monitor.checkCancelled();
			final Collection<FunctionPair> values = sourceFormatted.values();
			monitor.initialize(values.size());
			for (FunctionPair entry : values) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				if (!hasConflicts(entry, sourceFormatted, destFormatted)) {		// Check for conflicts in our current set
					finalPairs.add(entry);										// Accept immediately if no conflicts
					matchedSource.add(entry.getSourceNode());
					matchedDest.add(entry.getDestNode());
				}
				else {
					if (!matchedSource.contains(entry.getSourceNode()) &&
						!matchedDest.contains(entry.getDestNode())) {
						// If there is a conflict, but neither side has been matched yet,
						// decide if we throw out pair by comparing count ratios to ratioThresh

						// Compute "number of children" ratio
						double leftside =
							Math.min((double) entry.getSourceNode().getChildren().size(),
								(double) entry.getDestNode().getChildren().size());
						double rightside =
							Math.max((double) entry.getSourceNode().getChildren().size(),
								(double) entry.getDestNode().getChildren().size());
						double childRatio = (rightside == 0 ? 0 : leftside / rightside);		// Always <= 1.0

						// Compute byte length ratio
						leftside = (double) entry.getSourceNode().getLen() /
							(double) entry.getDestNode().getLen();
						double lenRatio = Math.min(leftside, 1 / leftside);						// Always <= 1.0
						if (lenRatio > ratioThresh && childRatio > ratioThresh) {	// Test both ratios against threshold
							// Keep (don't throw out) if both ratios exceed threshold
							sourceHoldOn.put(entry.getSourceNode(), entry);
							destHoldOn.put(entry.getDestNode(), entry);
						}
					}
				}
			}
			sourceFormatted = sourceHoldOn;			// Update our "current" set of sources
			destFormatted = destHoldOn;				// Update our "current" set of dests
			changed = (keepLen != values.size());	// Did we get any new pairs this round?
			keepLen = sourceHoldOn.values().size();
			sourceHoldOn = new HashSetValuedHashMap<FunctionNode, FunctionPair>();
			destHoldOn = new HashSetValuedHashMap<FunctionNode, FunctionPair>();
			ratioThresh = (2 + ratioThresh) / 3;	// Tighten the ratio threshold for next round
			// Move closer to 1.0 threshold (counts are exactly equal)
		}
		if (finalPairs.isEmpty()) {
			return;							// found no seeds
		}
		Collections.sort(finalPairs, CONF_COMPARATOR);

		double curConf = finalPairs.get(0).getConfResult();
		if (curConf < confThreshold) {
			Msg.warn(this, "Initial value of seed confidence too high (" + confThreshold +
				")...resetting seed confidence to " + curConf);
			confThreshold = curConf;
		}
		int lastIndex = findIndexMatchingThreshold(finalPairs, confThreshold);	// Last index that still meets threshold
		for (int i = 0; i < lastIndex + 1; ++i) {
			FunctionPair pair = finalPairs.get(i);
			seeds.add(pair);
		}
	}

	private static boolean hasConflicts(FunctionPair entry,
			MultiValuedMap<FunctionNode, FunctionPair> sourceFormatted,
			MultiValuedMap<FunctionNode, FunctionPair> destFormatted) {
		Collection<FunctionPair> sources = sourceFormatted.get(entry.getSourceNode());
		if (sources != null && sources.size() > 1) {
			return true;
		}
		Collection<FunctionPair> dests = destFormatted.get(entry.getDestNode());
		if (dests != null && dests.size() > 1) {
			return true;
		}
		return false;
	}

	/**
	 * Generate seed matches, placing the FunctionPair into the {@link #seeds} container.
	 * Seeds come from a) previously accepted matches and b) the {@link #discoveredMatches}
	 * @param matchSet is used to identify already accepted matches
	 * @param useAcceptedMatchesAsSeeds is true if previously accepted matches are considered seeds
	 * @param monitor is the TaskMonitor
	 * @return true if at least one seed was identified
	 * @throws CancelledException if the user cancels the correlation
	 */
	public boolean generateSeeds(VTMatchSet matchSet, boolean useAcceptedMatchesAsSeeds,
			TaskMonitor monitor) throws CancelledException {
		seeds = new HashSet<FunctionPair>();
		if (useAcceptedMatchesAsSeeds) {
			findAcceptedSeeds(matchSet, monitor);
		}
		chooseSeeds(monitor);
		return !seeds.isEmpty();
	}

	/**
	 * Establish what neighborhood generation strategy will be used
	 * @param round - which round to build a strategy for
	 * @return an array of NeighborGenerators
	 */
	private NeighborGenerator[] buildNeighborGenerators(int round) {
		ArrayList<NeighborGenerator> generatorList = new ArrayList<NeighborGenerator>();
		if (round == 0) {
			// For first round only collect new matches from "close" relationships (i.e. parent/child)
			// of the seed match.
			generatorList.add(new NeighborGenerator.Children(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.Parents(vectorFactory, impThreshold));
			// If the format includes explicit namespace information for functions,
			// use it when generating new matches.
			if (useNamespaceNeighbors) {
				generatorList.add(
					new NamespaceNeighborhood(vectorFactory, impThreshold, sourceNodes, destNodes));
			}
		}
		else {
			// For later rounds, also collect matches from more distant relationships (grandparent, grandchild, etc.)
			generatorList.add(new NeighborGenerator.Children(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.Parents(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.GrandChildren(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.Siblings(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.Spouses(vectorFactory, impThreshold));
			generatorList.add(new NeighborGenerator.GrandParents(vectorFactory, impThreshold));
			if (useNamespaceNeighbors) {
				generatorList.add(
					new NamespaceNeighborhood(vectorFactory, impThreshold, sourceNodes, destNodes));
			}
		}
		NeighborGenerator[] res = new NeighborGenerator[generatorList.size()];
		generatorList.toArray(res);
		return res;
	}

	/**
	 * Given a set of -seeds- iteratively extend the set of matches
	 * Loop greedily picking the best relative match, maintaining score sorts and other bookkeeping
	 * @param monitor is the TaskMonitor
	 * @return the final list of FunctionPairs as official matches
	 * @throws CancelledException if the user cancels the correlation
	 */
	public List<FunctionPair> doMatching(TaskMonitor monitor) throws CancelledException {
		matches = new LinkedList<FunctionPair>();

		for (int round = 0; round < 2; round++) {
			monitor.checkCancelled();
			NeighborGenerator[] generatorList = buildNeighborGenerators(round);
			if (round == 0) {
				monitor.setMessage("Matching round 1...");
				monitor.initialize(seeds.size());
				for (FunctionPair bridge : seeds) {
					monitor.checkCancelled();
					monitor.incrementProgress(1);
					acceptMatch(bridge);
					PotentialPair impliedPair = analyze(bridge, generatorList);
					if (impliedPair != null) {
						implications.add(impliedPair);
					}
				}
				seeds = null;		// seeds are no longer needed, free up memory
			}
			else {
				implications.clear();
				monitor.setMessage("Matching round 2...");
				monitor.initialize(matches.size());
				for (FunctionPair bridge : matches) {
					monitor.checkCancelled();
					monitor.incrementProgress(1);
					PotentialPair impliedPair = analyze(bridge, generatorList);
					if (impliedPair != null) {
						implications.add(impliedPair);
					}
				}
			}
			monitor.setMessage("Gathering matches for round " + (round + 1) + "...");
			int maxSize = implications.size();
			monitor.initialize(maxSize + 1);
			while (true) {
				monitor.checkCancelled();
				int size = implications.size();
				if (size > maxSize) {
					maxSize = size;
					monitor.setMaximum(maxSize + 1);
				}
				monitor.setProgress((maxSize - size) + 1);
				if (size == 0) {
					break;
				}
				PotentialPair bestImplied = implications.last();
				implications.remove(bestImplied);
				FunctionPair bridge =
					bestImplied.getSource().findEdge(bestImplied.getDestination());
				if (bridge != null) {
					acceptMatch(bridge);
					PotentialPair impliedPair = analyze(bridge, generatorList);
					if (impliedPair != null) {
						implications.add(impliedPair);
					}
				}
				// Let pair that produced this new match select a new PotentialPair
				PotentialPair impliedPair = analyze(bestImplied.getOrigin(), generatorList);
				if (impliedPair != null) {
					implications.add(impliedPair);
				}
				if (implications.isEmpty() || implications.last().getScore() < impThreshold) {
					break;
				}
			}
		}

		//Hole Patching
		LinkedList<FunctionPair> matchCopy = new LinkedList<FunctionPair>(matches);
		VectorCompare veccompare = new VectorCompare();
		monitor.setMessage("Patching holes...");
		monitor.initialize(matches.size());
		for (FunctionPair bridge : matchCopy) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (bridge.getSourceNode().getParents().size() == 1 &&
				bridge.getDestNode().getParents().size() == 1) {
				FunctionNode sp = bridge.getSourceNode().getParents().iterator().next();
				FunctionNode dp = bridge.getDestNode().getParents().iterator().next();
				if (sp.findEdge(dp) == null && !sp.isAcceptedMatch() && !dp.isAcceptedMatch()) {
					double similarity = sp.getVector().compare(dp.getVector(), veccompare);
					double confidence = vectorFactory.calculateSignificance(veccompare);
					FunctionPair rentBridge = new FunctionPair(sp, dp, similarity, confidence);
					acceptMatch(rentBridge);
				}
			}
		}

		return matches;
	}

	//Compare pairs by confidence.
	private static final Comparator<FunctionPair> CONF_COMPARATOR = new Comparator<FunctionPair>() {
		@Override
		public int compare(FunctionPair o1, FunctionPair o2) {
			return Double.compare(o2.getConfResult(), o1.getConfResult());
		}
	};

	/**
	 * Run through the VersionTrack match-set looking for matches between functions
	 * that have been formally marked as "accepted"
	 * @param myMatchSet is the match-set to examine
	 * @param monitor is the TaskMonitor
	 * @throws CancelledException if the user cancels the correlation
	 */
	private void findAcceptedSeeds(VTMatchSet myMatchSet, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Using accepted matches as seeds...");
		VTSession session = myMatchSet.getSession();
		VTAssociationManager associationManager = session.getAssociationManager();
		int associationCount = associationManager.getAssociationCount();
		monitor.initialize(associationCount);
		List<VTAssociation> associations = associationManager.getAssociations();
		Program sourceProgram = sourceNodes.getProgram();
		Program destinationProgram = destNodes.getProgram();

		for (VTAssociation association : associations) {
			monitor.checkCancelled();
			if (association.getType().equals(VTAssociationType.FUNCTION) &&
				association.getStatus() == VTAssociationStatus.ACCEPTED) {

				Address sourceAddress = association.getSourceAddress();
				Function sourceFunction = sourceProgram.getListing().getFunctionAt(sourceAddress);
				Address destinationAddress = association.getDestinationAddress();
				Function destinationFunction =
					destinationProgram.getListing().getFunctionAt(destinationAddress);

				if (sourceFunction != null && destinationFunction != null) {
					FunctionNode sn = sourceNodes.get(sourceAddress);
					if (sn != null) {
						FunctionNode dn = destNodes.get(destinationAddress);
						if (dn != null) {
							FunctionPair bridge = sn.findEdge(dn);
							if (bridge != null) {
								seeds.add(bridge);
							}
						}
					}
				}
			}
			monitor.incrementProgress(1);
		}
	}

	/**
	 * Given an accepted FunctionPair and methods for generating neighborhoods,
	 * For each generation method, generate a source neighborhood and a dest neighborhood
	 * and search for pairs between the two neighborhoods with the highest confidence score.
	 * 
	 * @param pair is the accepted FunctionPair
	 * @param generatorList is the list of neighborhood generators
	 * @return the highest confidence pair across all pairs of neighborhoods
	 */
	private PotentialPair analyze(FunctionPair pair, NeighborGenerator[] generatorList) {
		FunctionNode sourceNode = pair.getSourceNode();
		FunctionNode destNode = pair.getDestNode();
		double confResult = pair.getConfResult();

		double implicationScore = 0;
		PotentialPair bestImplied = null;

		for (NeighborGenerator generator : generatorList) {
			NeighborhoodPair nPair = generator.generate(sourceNode, destNode);
			PotentialPair srcToDestPair =
				calculateBestNeighbor(nPair.srcNeighbors, nPair.destNeighbors, confResult);
			if (srcToDestPair.getScore() > implicationScore) {
				implicationScore = srcToDestPair.getScore();
				bestImplied = srcToDestPair;
			}
			PotentialPair destToSrcPair =
				calculateBestNeighbor(nPair.destNeighbors, nPair.srcNeighbors, confResult);
			destToSrcPair.swap();		// PotentialPair is returned with opposite from and to nodes
			if (destToSrcPair.getScore() > implicationScore) {
				implicationScore = destToSrcPair.getScore();
				bestImplied = destToSrcPair;
			}
		}
		if (bestImplied != null) {
			bestImplied.setOrigin(pair);
		}
		return bestImplied;
	}

	/**
	 * Among a -range- of pairs with the same score, return a pair that does not conflict with
	 * any other pair in the range, i.e. the source and destination of the pair or not
	 * involved in another pair (with the same score).
	 * @param potentialPairs is the (ordered) set of pairs
	 * @param firstIndex is the start index of the range
	 * @param lastIndex is the last index of the range
	 * @return an unconflicted pair or null if none exist
	 */
	private static PotentialPair unconflictedPair(ArrayList<PotentialPair> potentialPairs,
			int firstIndex, int lastIndex) {
		for (int i = firstIndex; i <= lastIndex; i++) {
			FunctionNode myFrom = potentialPairs.get(i).getSource();
			FunctionNode myTo = potentialPairs.get(i).getDestination();
			boolean useMe = true;
			for (int j = firstIndex; j <= lastIndex; j++) {				// Look for conflicts in entries with same score
				if (i == j) {
					continue;
				}
				FunctionNode yourFrom = potentialPairs.get(j).getSource();
				FunctionNode yourTo = potentialPairs.get(j).getDestination();
				if (myFrom == yourFrom || myTo == yourTo) {
					useMe = false;									// Conflict found. Can't use this one.
					break;
				}
			}
			if (useMe) {											// No conflict found
				return potentialPairs.get(i);						// Use this entry
			}
		}
		return null;
	}

	/**
	 * Adjust an original confidence score between functions -a- and -b-
	 * based on the likelihood of children matching and parents matching.
	 * @param conf is the original confidence
	 * @param a is one side of the function pair
	 * @param b is the other side
	 * @return the adjusted score
	 */
	private static double adjustConfidenceScore(double conf, FunctionNode a, FunctionNode b) {
		final int childrenSize = b.getChildren().size();
		double ratio = (childrenSize == 0 ? 0 : (double) a.getChildren().size() / childrenSize);
		final double kidRatio = Math.min(ratio, 1 / ratio);
		final int parentsSize = b.getParents().size();
		ratio = (parentsSize == 0 ? 0 : (double) a.getParents().size() / parentsSize);
		final double rentRatio = Math.min(ratio, 1 / ratio);

		ratio = (double) a.getLen() / b.getLen();
		final double lenRatio = Math.min(ratio, 1 / ratio);
		return 0.25 * conf * lenRatio * (1 + kidRatio) * (1 + rentRatio);
	}

	/**
	 * Find the first PotentialPair where there is no conflict.
	 * Sort the pairs based on score, and divide them into ranges of equal score.
	 * Look for the first PotentialPair whose source and dest are not involved with any
	 * other pair within an equal score range.
	 * @param potentialPairs is the array of pairs
	 * @return the first (highest scoring) unconflicted pair (or null)
	 */
	private static PotentialPair findFirstUnconflictedPair(
			ArrayList<PotentialPair> potentialPairs) {
		Collections.sort(potentialPairs);			// Sort pairs based on score
		int lastIndex = potentialPairs.size() - 1;
		while (lastIndex >= 0) {
			double score = potentialPairs.get(lastIndex).getScore();
			int firstIndex = lastIndex - 1;
			while (firstIndex >= 0 && potentialPairs.get(firstIndex).getScore() >= score) {
				firstIndex -= 1;
			}
			PotentialPair bestPair = unconflictedPair(potentialPairs, firstIndex + 1, lastIndex);
			if (bestPair != null) {
				return bestPair;
			}
			lastIndex = firstIndex;
		}

		return PotentialPair.EMPTY_PAIR;	// No match found. We get here in the case of conflict-only matrices.	
	}

	/**
	 * Given matching neighborhoods, look at "matrix" of scores for pairs across them.
	 * Return the most likely pair.
	 * @param aNeighbors is the first neighborhood
	 * @param bNeighbors is the second neighborhood
	 * @param confResult is the confidence score associated with the accepted match
	 * @return the most likely pair as a PotentialPair
	 */
	private PotentialPair calculateBestNeighbor(Set<FunctionNode> aNeighbors,
			Set<FunctionNode> bNeighbors, double confResult) {
		ArrayList<PotentialPair> potentialPairs = new ArrayList<PotentialPair>();
		PotentialPair bestPair = PotentialPair.EMPTY_PAIR;
		int bestCount = 0;			// Number of pairs with the same (currently) best score

		// CRITICAL LOOP
		for (FunctionNode relative : aNeighbors) {						// For every function in the source neighborhood
			if (relative.isAcceptedMatch()) {
				continue;
			}
			double bestAdjustedScore = 0;								// Best score you're seeing for just this relative.
			double relSum = 0;											// Sum of relative's scores for associates...for normalizing.
			double bestOriginalScore = 0;								// So that we can recover the entry without computation.
			FunctionNode bestRelAssoc = null;							// The highest scoring associate
			// CRITICAL INNER LOOP
			Iterator<Entry<FunctionNode, FunctionPair>> iter = relative.getAssociateIterator();
			while (iter.hasNext()) {									// Run through every putative match to -relative-
				Entry<FunctionNode, FunctionPair> entry = iter.next();
				final FunctionNode associate = entry.getKey();
				final double value = entry.getValue().getConfResult();
				if (bNeighbors.contains(associate)) {					// Does the dest side of the match lie in dest neighborhood
					double entryAdjusted = adjustConfidenceScore(value, relative, associate);
					relSum += entryAdjusted;							// Keep track of score sum for normalization
					if (entryAdjusted >= bestAdjustedScore) {			// Keep track of highest scoring pair
						bestAdjustedScore = entryAdjusted;
						bestRelAssoc = associate;
						bestOriginalScore = value;
					}
				}
			}

			if (relSum > 0) {
				// Compute a final score that takes into account the dimensions of the neighborhoods
				// and scores of other potential pairs across the neighborhoods
				double tempMax = bNeighbors.size() * (bestOriginalScore + confResult) *
					bestAdjustedScore / relSum;

				PotentialPair newPair = new PotentialPair(relative, bestRelAssoc, tempMax);
				potentialPairs.add(newPair);
				if (tempMax > bestPair.getScore()) {				// We have seen a new maximum.
					bestPair = newPair;								// Keep track of the new best
					bestCount = 1;									// Restart the counter
				}
				else if (tempMax == bestPair.getScore()) {			// A tie score with the current best
					bestCount += 1;
				}

			}
		}

		if (bestCount == 0 || bestPair.getScore() == 0) {
			return PotentialPair.EMPTY_PAIR;		// The default null object passed for nothing found.
		}

		if (bestCount == 1) {						// There is a unique best entry.  Use it.
			return bestPair;
		}

		return findFirstUnconflictedPair(potentialPairs);		// The best pair is a tie, we need to go deeper into the list
	}
}
