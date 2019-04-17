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
package ghidra.feature.vt.api.correlator.program;

import static ghidra.feature.vt.api.correlator.program.VTAbstractReferenceProgramCorrelatorFactory.*;

import java.util.*;
import java.util.Map.Entry;

import generic.DominantPair;
import generic.lsh.vector.LSHCosineVectorAccum;
import generic.lsh.vector.VectorCompare;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract parent class for Version Tracking Reference Program Correlators.
 */
public abstract class VTAbstractReferenceProgramCorrelator extends VTAbstractProgramCorrelator {

	private static final int MAX_DEPTH = 30;
	private static final int TOP_N = 5;
	private static final double DIFFERENTIAL = 0.2;
	private static final double EQUALS_EPSILON = 0.00001;

	private String correlatorName;
	private HashMap<Address, LSHCosineVectorAccum> srcFuncAddresstoVectorMap;
	private HashMap<Address, LSHCosineVectorAccum> destFuncAddresstoVectorMap;

	private Program sourceProgram;
	private Program destinationProgram;
	private Listing sourceListing;
	private Listing destinationListing;

	/**
	 * Correlator class constructor.
	 * @param serviceProvider The {@code ServiceProvider}.
	 * @param sourceProgram The source {@code Program}.
	 * @param sourceAddressSet The {@code AddressSetView} for the source program.
	 * @param destinationProgram The destination {@code Program}.
	 * @param destinationAddressSet The {@code AddressSetView} for the destination program.
	 * @param correlatorName The correlator name string passed from the factory.
	 * @param options {@code ToolOptions}
	 */
	VTAbstractReferenceProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, String correlatorName, ToolOptions options) {
		// Call the constructor for the parent class.
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
		this.correlatorName = correlatorName;

		this.sourceProgram = sourceProgram;
		this.destinationProgram = destinationProgram;

		this.sourceListing = sourceProgram.getListing();
		this.destinationListing = destinationProgram.getListing();
	}

	@Override
	public String getName() {
		return correlatorName;
	}

	/**
	 * First generates the sourceDictionary from the source program and matchSet, 
	 * then finds the destinations corresponding to the matchSet and the 
	 * sourceDictionary using the preset similarity and confidence thresholds.
	 *  
	 * @param matchSet VTMatchSetDB containing all existing matches sorted into 
	 * subsets corresponding to the generating correlators.
	 * @param monitor the task monitor
	 * @throws CancelledException the process cancellation exception
	 */
	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {

		double minbits = getOptions().getDouble(CONFIDENCE_THRESHOLD, CONFIDENCE_THRESHOLD_DEFAULT);
		double similarity_threshold =
			getOptions().getDouble(SIMILARITY_THRESHOLD, SIMILARITY_THRESHOLD_DEFAULT);

		monitor.setMessage("Finding reference features");
		extractReferenceFeatures(matchSet, monitor);

		monitor.setMessage("Finding destination functions");
		try {
			findDestinations(matchSet, similarity_threshold, minbits, monitor);
		}
		catch (Exception e) {
			throw new RuntimeException("problem with parallel decompiler", e);
		}
	}

	/**
	 * findDestinations updates matchSet with non-null VTMatchInfo members returned from transform.
	 * For each of the entries in the destinationMap = {destMatchAddr:[list of source references]}, 
	 * we test all pairs [list of source references] x [list of destination references] 
	 * 
	 * </br> 
	 * Note: {@code destinationMap} is a class variable set by {@code extractReferenceFeatures}
	 * 
	 * @param matchSet The {@code VTMatchSet} for the current session (non-transitive).
	 * @param similarityThreshold The {@code double} threshold passed to {@code transform}
	 * @param minbits The {@code double} minbits value passed to {@code transform}.
	 * @param monitor The {@code TaskMonitor} (non-transitive).
	 */
	protected void findDestinations(final VTMatchSet matchSet, final double similarityThreshold,
			double minbits, final TaskMonitor monitor) {

		monitor.initialize(destFuncAddresstoVectorMap.size());
		for (Entry<Address, LSHCosineVectorAccum> destEntry : destFuncAddresstoVectorMap.entrySet()) {
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);

			// Get the function CONTAINING the ACCEPTED match destination address
			Function destFunc = destinationListing.getFunctionAt(destEntry.getKey());
			LSHCosineVectorAccum dstVector = destEntry.getValue();

			// Get the set of possible matches, neighbors, in the SourceProgram
			HashMap<Address, DominantPair<Double, VectorCompare>> srcNeighbors = new HashMap<>();

			for (Entry<Address, LSHCosineVectorAccum> srcEntry : srcFuncAddresstoVectorMap.entrySet()) {
				Address srcAddr = srcEntry.getKey();
				LSHCosineVectorAccum srcVector = srcEntry.getValue();

				VectorCompare veccompare = new VectorCompare();
				Double similarity = dstVector.compare(srcVector, veccompare);

				DominantPair<Double, VectorCompare> compareOut =
					new DominantPair<>(similarity, veccompare);

				if (dstVector.compare(srcVector, veccompare) > 0) {
					srcNeighbors.put(srcAddr, compareOut);
				}
			}

			List<VTMatchInfo> members = transform(matchSet, destFunc, dstVector, srcNeighbors,
				similarityThreshold, minbits, monitor);

			for (VTMatchInfo member : members) {
				if (member != null) {
					matchSet.addMatch(member);
				}
			}
		}

	}

	/**
	 * Scoring Mechanism: determines destination similarity and confidence for each 
	 * of the sourceNeighbors and if similarity passes the threshold and confidence passes minbits, 
	 * then VTMatchInfo will be created and added to the result.
	 *  
	 * @param matchSet - The returned {@code VTMatchSet} for this correlator. 
	 * @param destinationFunction - A {@code Function} in the destination program that references an existing accepted match.
	 * @param destinationVector - The destination function's feature vector.
	 * @param neighbors - The set data for possible sourceFunction matches for destinationFunction.
	 * @param similarityThreshold - The user defined similarity scoring threshold (expected to be between 0 and 1).
	 * @param minbits - The user defined confidence threshold. 
	 * @param monitor - {@code TaskMonitor} 
	 * @return {@code List<VTMatchInfo>} result
	 */
	private List<VTMatchInfo> transform(VTMatchSet matchSet, Function destinationFunction,
			LSHCosineVectorAccum destinationVector,
			HashMap<Address, DominantPair<Double, VectorCompare>> neighbors,
			double similarityThreshold, double minbits, TaskMonitor monitor) {

		boolean refineResult = getOptions().getBoolean(REFINE_RESULTS, REFINE_RESULTS_DEFAULT);

		Address destinationAddress = destinationFunction.getEntryPoint();
		int destinationLength = (int) destinationFunction.getBody().getNumAddresses();
		List<VTMatchInfo> result = new ArrayList<>();

		for (Entry<Address, DominantPair<Double, VectorCompare>> neighbor : neighbors.entrySet()) {
			if (monitor.isCancelled()) {
				break;
			}

			Address sourceAddr = neighbor.getKey();

			/* compare using LSHCosineVector.compare function
			 * --> similarity is the normalized dot product of the two vectors
			 */
			double similarity = neighbor.getValue().first;
			VectorCompare veccompare = neighbor.getValue().second;
			veccompare.fillOut();

			double confidence = veccompare.dotproduct;

			if (similarity < similarityThreshold || Double.isNaN(similarity)) {
				continue;
			}

			if (confidence < minbits) {
				continue;
			}
			confidence *= 10.0; // remove when getting rid of log10 stuff

			VTMatchInfo match = new VTMatchInfo(matchSet);

			Function sourceFunction = sourceListing.getFunctionAt(sourceAddr);
			Address sourceAddress = sourceFunction.getEntryPoint();
			int sourceLength = (int) sourceFunction.getBody().getNumAddresses();
			match.setSimilarityScore(new VTScore(similarity));
			match.setConfidenceScore(new VTScore(confidence));
			match.setSourceLength(sourceLength);
			match.setDestinationLength(destinationLength);
			match.setSourceAddress(sourceAddress);
			match.setDestinationAddress(destinationAddress);
			match.setTag(null);
			match.setAssociationType(VTAssociationType.FUNCTION);
			result.add(match);
		}

		if (refineResult) {
			result = refine(result);
		}
		return result;
	}

	private static final Comparator<VTMatchInfo> SCORE_COMPARATOR = new Comparator<VTMatchInfo>() {
		@Override
		public int compare(VTMatchInfo o1, VTMatchInfo o2) {
			return o2.getSimilarityScore().compareTo(o1.getSimilarityScore());
		}
	};

	private List<VTMatchInfo> refine(List<VTMatchInfo> list) {

		int topN;
		Collections.sort(list, SCORE_COMPARATOR);

		// take the top N + 1 (to catch duplicates across the N boundary)
		topN = Math.min(TOP_N + 1, list.size());
		list = list.subList(0, topN);

		// remove things that are "very equal"
		if (list.size() > 1) {
			double previousScore = list.get(0).getSimilarityScore().getScore();
			int cutoffIndex = 1;
			for (int ii = 1; ii < list.size(); ++ii) {
				double currentScore = list.get(ii).getSimilarityScore().getScore();
				if (currentScore > previousScore - EQUALS_EPSILON) {
					--cutoffIndex;
					break;
				}
				++cutoffIndex;
				previousScore = currentScore;
			}
			list = list.subList(0, cutoffIndex);
		}

		// take the top N
		topN = Math.min(TOP_N, list.size());
		list = list.subList(0, topN);

		// remove things more than differential score from previous
		if (list.size() > 1) {
			double bestScore = list.get(0).getSimilarityScore().getScore();
			int cutoffIndex = list.size();
			for (int ii = 1; ii < list.size(); ++ii) {
				if (list.get(ii).getSimilarityScore().getScore() < bestScore - DIFFERENTIAL) {
					cutoffIndex = ii;
					break;
				}
			}
			list = list.subList(0, cutoffIndex);
		}
		return list;
	}

	/**
	 * accumulateFunctionReferences recursively traces the reference chains from a given address 
	 * and returns by reference a list of functions found along the reference chain.
	 * 
	 * @param depth - The initial recursion depth
	 * @param list  - A function accumulation list that is updated by this function
	 * @param refManager - {@inheritDoc ReferenceManager}
	 * @param funManager - {@inheritDoc FunctionManager}
	 * @param listing - The Program listing
	 * @param address - An address represents a location in a program
	 */
	private void accumulateFunctionReferences(int depth, List<Function> list,
			ReferenceManager refManager, FunctionManager funManager, Listing listing,
			Address address) {

		// Do NOT proceed if the max recursion depth has been reached
		if (depth >= MAX_DEPTH) {
			return;
		}
		/* If address corresponds to a Thunk Function, in addition to following back references, 
		 * you should collect back-thunk-addresses (not included in references) by using the 
		 * method Function.getFunctionThunkAddresses (Elf programs can have thunks which do 
		 * not have a forward reference but thunk another function).  You may also need to dedup
		 *  your list of functions returned if this could cause fallout.  In addition, you may 
		 *  need to watch out for recursion loops which could occur (i.e., a function pointer which 
		 *  has a secondary reference to itself - contrived example). 		 * 
		 */

		// Check for Thunk Function
		Function addressFunction = funManager.getFunctionAt(address);
		if (addressFunction != null) {
			Address[] thunkAddresses = addressFunction.getFunctionThunkAddresses();
			if (thunkAddresses != null) {
				for (Address thunkAddress : thunkAddresses) {
					if (depth < MAX_DEPTH) {
						accumulateFunctionReferences(depth + 1, list, refManager, funManager,
							listing, thunkAddress);
					}
				}
			}
		}

		// Handle References to the address
		ReferenceIterator ii = refManager.getReferencesTo(address);
		while (ii.hasNext()) {
			Reference reference = ii.next();
			Address fromAddress = reference.getFromAddress();
			CodeUnit codeUnit = listing.getCodeUnitAt(fromAddress);
			// if the code unit at the location of the reference is an Instruction, then get the function
			// where the reference occurs and determine if it passes the basic VT function match test set above
			// if so, add it to the function accumulation list for the original reference
			if (codeUnit instanceof Instruction) {
				Function function = funManager.getFunctionContaining(fromAddress);

				if (function != null) {
					if (!function.isThunk()) {
						list.add(function);
					}
					else {
						//If a thunk function recurse
						accumulateFunctionReferences(depth + 1, list, refManager, funManager,
							listing, function.getEntryPoint());
					}
				}
				else {
					//Msg.warn(this, "no function for instruction at " + fromAddress +
					//	" for reference " + address);
				}
			}
			else if (codeUnit instanceof Data) {
				if (depth < MAX_DEPTH) {
					accumulateFunctionReferences(depth + 1, list, refManager, funManager, listing,
						fromAddress);
				}
			}
			else {
				//Msg.warn(this, "weird non-instruction non-data codeunit: " + codeUnit);
			}
		}
	}

	/**
	 * Boolean function used to check that a match association is of the correct type (e.g. DATA or FUNCTION) for the given correlator.
	 * Called by extractReferenceFeatures. 
	 * 
	 * @param matchAssocType the type of match.
	 * @return True or False
	 */
	protected abstract boolean isExpectedRefType(VTAssociationType matchAssocType);

	protected abstract boolean isExpectedRefType(Reference myRef);

	/**
	 * extractReferenceFeatures is the core of the reference algorithm.  Each accepted match becomes a unique feature.
	 * At the end, all the source and destination functions will have "vectors" of these features, which
	 * are unique match ids.  Then the LSH dictionary can be made from the source and we can look for matches   
	 * in the destination.
	 * 
	 * @param matchSet The VTMatchSet of previously user-accepted matches.
	 * @param monitor TaskMonitor
	 */
	protected void extractReferenceFeatures(VTMatchSet matchSet, TaskMonitor monitor) {

		// Make source and destination maps that will be populated here.
		srcFuncAddresstoVectorMap = new HashMap<>();
		destFuncAddresstoVectorMap = new HashMap<>();

		// Get function managers for Source and Destination Programs
		FunctionManager srcFuncManager = sourceProgram.getFunctionManager();
		FunctionManager destFuncManager = destinationProgram.getFunctionManager();

		// get total function counts for computing probabilities 
		int srcFunctionCount = srcFuncManager.getFunctionCount();
		int destFunctionCount = destFuncManager.getFunctionCount();

		// setup session
		final VTSession session = matchSet.getSession();
		int total = 0;
		HashMap<String, VTMatchSet> dedupedMatchSets = new HashMap<>();
		for (VTMatchSet ms : session.getMatchSets()) {
			String name = ms.getProgramCorrelatorInfo().getName();
			if (name.equals(correlatorName) ||
				(dedupedMatchSets.containsKey(name) && ms.getID() < dedupedMatchSets.get(name).getID())) {
				continue;
			}
			dedupedMatchSets.put(name, ms);

			// get total number of matches in matchSets List
			total += ms.getMatchCount();
		}

		final Collection<VTMatchSet> matchSets = dedupedMatchSets.values();
		monitor.initialize(total);

		/**
		 * Loop through the matchSets in order to get total source and dest reference counts that pass the filter.
		 * Only add matches that pass the isExpectedRefType filter test to the hash tables.
		 */

		Map<VTMatch, ArrayList<Function>> sourceRefMap = new HashMap<>();
		Map<VTMatch, ArrayList<Function>> destinationRefMap = new HashMap<>();

		for (VTMatchSet ms : matchSets) {
			final Collection<VTMatch> matches = ms.getMatches();
			for (VTMatch match : matches) {
				// update monitor
				if (monitor.isCancelled()) {
					return;
				}
				monitor.incrementProgress(1);

				//check match association type and status
				final VTAssociation association = match.getAssociation();
				final Address sourceAddress = association.getSourceAddress();
				final Address destinationAddress = association.getDestinationAddress();

				if (isExpectedRefType(association.getType()) &&
					association.getStatus() == VTAssociationStatus.ACCEPTED) {

					// populate sourceReferences by passing it to accumulateFunctionReferences
					ArrayList<Function> sourceReferences = new ArrayList<>();
					accumulateFunctionReferences(0, sourceReferences,
						sourceProgram.getReferenceManager(), srcFuncManager, sourceListing,
						sourceAddress);

					ArrayList<Function> destinationReferences = new ArrayList<>();
					accumulateFunctionReferences(0, destinationReferences,
						destinationProgram.getReferenceManager(), destFuncManager,
						destinationListing, destinationAddress);

					final int sourceReferenceCountTo = sourceReferences.size();
					final int destinationReferenceCountTo = destinationReferences.size();

					//If either of the reference lists is empty, skip adding them to the hashtable
					if (sourceReferenceCountTo == 0 || destinationReferenceCountTo == 0) {
						continue;
					}

					// Fill Hashtable for use in next loop
					sourceRefMap.put(match, sourceReferences);
					destinationRefMap.put(match, destinationReferences);
				}
			}
		}
		monitor.setMessage("Adding ACCEPTED matches to feature vectors.");
		int featureID = 1;
		// for each match that passed the filter above, score it
		for (VTMatch match : sourceRefMap.keySet()) {
			// update monitor
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);

			// If the match is in one Hashtable it will be in the other by the joint construction above
			if (sourceRefMap.get(match) != null) {

				/**
				 * Compute raw percentages for the sources and destination counts 
				 * as ratios 
				 * (total references to the match):(total number of references of the correct type)
				 */

				// Compute entropy of the system for the given match
				Set<Function> srcRefFuncs = new HashSet<>(sourceRefMap.get(match));
				Set<Function> destRefFuncs = new HashSet<>(destinationRefMap.get(match));

				// take the average probability that the feature appears any one function (in either source or dest)
				double altPraw = (double) (srcRefFuncs.size() + destRefFuncs.size()) /
					(srcFunctionCount + destFunctionCount);
				final double weight = Math.sqrt(-Math.log(altPraw));

				// By the construction above, there may be duplicate functions in the RefMaps
				for (Function function : sourceRefMap.get(match)) {
					//If function is not in the HashMap, add it
					LSHCosineVectorAccum vector = srcFuncAddresstoVectorMap.get(function.getEntryPoint());
					if (vector == null) {
						vector = new LSHCosineVectorAccum();
						srcFuncAddresstoVectorMap.put(function.getEntryPoint(), vector);
					}
					vector.addHash(featureID, weight);
				}

				for (Function function : destinationRefMap.get(match)) {
					LSHCosineVectorAccum vector = destFuncAddresstoVectorMap.get(function.getEntryPoint());
					if (vector == null) {
						vector = new LSHCosineVectorAccum();
						destFuncAddresstoVectorMap.put(function.getEntryPoint(), vector);
					}
					vector.addHash(featureID, weight);
				}
				++featureID;
			} //end if match association 
		}

		/* At this point the vectors in the sourceMap and the destinationMap contain log weights for 
		 * the probability that ACCEPTED MATCHED features appear in any one function in the system.
		 * Each map has the key:value pair = refFunction:featureVector.
		 * In order to account unmatched/unaccepted matches that appear in the key set that consists of 
		 * possibly correlated functions, we can consider the cost of a reference switching
		 * and the cost of a reference being dropped or picked up between versions.
		 * 
		 * Theoretically this should be dependent on the probability of the referenced element occurring, 
		 * but for the moment we'll consider the model for a generalized switch and drop/pickup. 
		 */
		monitor.setMessage("Adding unmatched references to feature vectors.");

		double pSwitch = 0.5;
		double uniqueWeight = Math.sqrt(-Math.log(pSwitch)); //arbitrary weight used to provide negative correlation

		/*
		 * Update Source Vectors
		 */
		for (Address addr : srcFuncAddresstoVectorMap.keySet()) {
			Function func = srcFuncManager.getFunctionAt(addr);

			CodeUnitIterator iter = sourceProgram.getListing().getCodeUnits(func.getBody(), true);
			int totalRefs = 0;
			while (iter.hasNext()) {
				CodeUnit cu = iter.next();
				Reference[] memRefs = cu.getReferencesFrom();

				for (Reference memRef : memRefs) {
					if (isExpectedRefType(memRef)) {
						++totalRefs;
					}
				}
			}
			LSHCosineVectorAccum srcVector = srcFuncAddresstoVectorMap.get(addr);
			int numEntries = srcVector.numEntries();
			for (int i = 0; i < (totalRefs - numEntries); i++) {
				srcVector.addHash(featureID, uniqueWeight);
				++featureID;
			}
		}
		/*
		 * Update Destination Vectors
		 */
		for (Address addr : destFuncAddresstoVectorMap.keySet()) {
			Function func = destFuncManager.getFunctionAt(addr);
			CodeUnitIterator iter = destinationListing.getCodeUnits(func.getBody(), true);
			int totalRefs = 0;
			while (iter.hasNext()) {
				CodeUnit cu = iter.next();
				Reference[] memRefs = cu.getReferencesFrom();
				for (Reference memRef : memRefs) {
					if (isExpectedRefType(memRef)) {
						++totalRefs;
					}
				}
			}
			LSHCosineVectorAccum dstVector = destFuncAddresstoVectorMap.get(addr);
			int numEntries = dstVector.numEntries();
			for (int i = 0; i < (totalRefs - numEntries); i++) {
				dstVector.addHash(featureID, uniqueWeight);
				++featureID;
			}
		}
	}
}
