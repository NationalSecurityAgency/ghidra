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
package ghidra.feature.fid.service;

import java.util.*;

import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.hash.FidHasher;
import ghidra.feature.fid.plugin.HashLookupListMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for producing FID search results for a functions in a single program.
 * It holds program specific context and caches
 */
public class FidProgramSeeker {
	/**
	 * Comparator to sort hash matches by decreasing significance.
	 */
	private static final Comparator<HashMatch> MOST_SIGNIFICANT = new Comparator<HashMatch>() {
		@Override
		public int compare(HashMatch o1, HashMatch o2) {
			return o1.getOverallScore() < o2.getOverallScore() ? 1
					: o1.getOverallScore() > o2.getOverallScore() ? -1 : 0;
		}
	};

	public final int MAX_NUM_PARENTS_FOR_SCORE = 500; // Limit number of (useless) parent (caller) functions

	private final int MAX_CACHE_SIZE = 2000000; // Maximum number of FidQuadHash cached

	private final float scoreThreshold; // Code unit score a function must achieve to be considered a match
	private final int mediumHashCodeUnitLengthLimit;
	private final FidQueryService fidQueryService;
	private final Program program;
	private final FIDFixedSizeMRUCachingFactory cacheFactory;

	/**
	 * Creates a seek object.
	 * @param controller the FID database service
	 * @param program the program for which to resolve names
	 * @param hasher the FID hasher
	 * @param shortHashCodeUnitLength the short hash size
	 * @param mediumHashCodeUnitLengthLimit the medium hash size
	 */
	public FidProgramSeeker(FidQueryService fidQueryService, Program program, FidHasher hasher,
			byte shortHashCodeUnitLength, byte mediumHashCodeUnitLengthLimit,
			float scoreThreshold) {
		this.fidQueryService = fidQueryService;
		this.program = program;
		this.scoreThreshold = scoreThreshold;
		this.mediumHashCodeUnitLengthLimit = mediumHashCodeUnitLengthLimit;
		FidHasherFactory factory = new FidHasherFactory(hasher);
		int cacheSize = program.getFunctionManager().getFunctionCount();
		cacheSize = (cacheSize < 100) ? 100 : cacheSize;
		cacheSize = (cacheSize > MAX_CACHE_SIZE) ? MAX_CACHE_SIZE : cacheSize;
		this.cacheFactory = new FIDFixedSizeMRUCachingFactory(factory, cacheSize);
	}

	public static ArrayList<Function> getChildren(Function function, boolean followThunks) {
		Program program = function.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();
		HashSet<Address> alreadyDone = new HashSet<Address>();
		ArrayList<Function> funcList = new ArrayList<Function>();
		AddressIterator referenceIterator =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);
		for (Address address : referenceIterator) {
//			monitor.checkCanceled();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			for (Reference reference : referencesFrom) {
				Address toAddress = reference.getToAddress();
				if (reference.getReferenceType().isCall() && !alreadyDone.contains(toAddress)) {
					Function child = functionManager.getFunctionContaining(toAddress);
					if (child != null) {
						if (followThunks && child.isThunk()) {
							child = child.getThunkedFunction(true);
						}
						funcList.add(child);
						alreadyDone.add(toAddress);
					}
				}
			}
		}
		return funcList;
	}

	/**
	 * Add the children of the function to the hash family.
	 * @param family the family
	 * @param function the function
	 * @param monitor a task monitor
	 * @throws MemoryAccessException if a function body was inexplicably inaccessible
	 * @throws CancelledException
	 */
	private void addChildren(HashFamily family, Function function, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
//		SymbolTable symbolTable = function.getProgram().getSymbolTable();
		ArrayList<Function> children = getChildren(function, true);
		for (Function relation : children) {
			monitor.checkCanceled();
			FidHashQuad hash = cacheFactory.get(relation);
			if (hash != null) {
				family.addChild(hash);
			}
//			else {
//				Symbol[] symbols = symbolTable.getSymbols(relation.getEntryPoint());
//				if (symbols != null && symbols.length != 0) {
//					for (Symbol symbol : symbols) {
//						if (symbol.isPrimary() && symbol.getSource() != SourceType.DEFAULT) {
//							String unresolvedChildName = symbol.getName();
//							family.addUnresolvedChild(unresolvedChildName);
//							break;
//						}
//					}
//				}
//			}
		}
	}

	public static ArrayList<Function> getParents(Function function, boolean followThunks) {
		Program program = function.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		ReferenceManager referenceManager = program.getReferenceManager();
		HashSet<Address> alreadyDone = new HashSet<Address>();
		ArrayList<Function> funcList = new ArrayList<Function>();
		int size = 0;
		Address curAddr = function.getEntryPoint();
		Address[] thunkAddresses = null;
		if (followThunks) {
			thunkAddresses = function.getFunctionThunkAddresses();
			if (thunkAddresses != null) {
				size = thunkAddresses.length;
			}
		}
		int pos = -1;
		for (;;) {
			ReferenceIterator referenceIterator = referenceManager.getReferencesTo(curAddr);
			for (Reference reference : referenceIterator) {
				// monitor.checkCanceled();
				Address fromAddress = reference.getFromAddress();
				if (reference.getReferenceType().isCall()) {
					Function par = functionManager.getFunctionContaining(fromAddress);
					if (par != null) {
						Address entryPoint = par.getEntryPoint();
						if (!alreadyDone.contains(entryPoint)) {
							funcList.add(par);
							alreadyDone.add(entryPoint);
						}
					}
				}
			}
			pos += 1;
			if (pos >= size) {
				break;
			}
			curAddr = thunkAddresses[pos];
		}

		return funcList;
	}

	/**
	 * Add the parents of the function to the hash family.
	 * @param family the family
	 * @param function the function
	 * @param monitor is a task monitor
	 * @throws MemoryAccessException if a function body was inexplicably inaccessible
	 * @throws CancelledException
	 */
	private void addParents(HashFamily family, Function function, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		ArrayList<Function> parents = getParents(function, true);
		for (Function relation : parents) {
			monitor.checkCanceled();
			FidHashQuad hash = cacheFactory.get(relation);
			if (hash != null) {
				family.addParent(hash);
			}
		}
	}

	/**
	 * Given HashFamily for a function, lookup possible matches and mint FidSearchResult objects
	 * @param function the function
	 * @param family the hash family
	 * @param monitor a task monitor
	 * @return the FidSearchResult describing any discovered matches
	 * @throws CancelledException if the user cancels
	 */
	private FidSearchResult processMatches(Function function, HashFamily family,
			TaskMonitor monitor) throws CancelledException {
		List<HashMatch> hashMatches = lookupFamily(family, monitor);
		FidSearchResult searchResult = null;
		if (!hashMatches.isEmpty()) {
			if (hashMatches.size() == 1) {
				FidMatchScore hashMatch = hashMatches.get(0);
				searchResult = makeSingletonMatch(function, family, hashMatch);
			}
			else {
				ArrayList<HashMatch> culledHashMatches = new ArrayList<HashMatch>();
				culledHashMatches.add(hashMatches.get(0));
				final float maxOverall = hashMatches.get(0).getOverallScore();
				for (int ii = 1; ii < hashMatches.size(); ++ii) {
					monitor.checkCanceled();
					HashMatch hashMatch = hashMatches.get(ii);
					if (hashMatch.getOverallScore() < maxOverall) {
						break;
					}
					culledHashMatches.add(hashMatch);
				}
				if (culledHashMatches.size() == 1) {
					FidMatchScore hashMatch = culledHashMatches.get(0);
					searchResult = makeSingletonMatch(function, family, hashMatch);
				}
				else {
					searchResult = makeAllMatches(function, family, culledHashMatches, monitor);
				}
			}
		}
		return searchResult;
	}

	/**
	 * We couldn't disambiguate, but it's OK to return multiple results to the analyzer
	 * (which may decide to throw them all out, or mark all of them, or something in between).
	 * @param function the function
	 * @param family is the collection of hashes associated with function
	 * @param culledHashMatches list of functions at the appropriate significance for the multiple matches
	 * @param monitor a task monitor
	 * @return the FidSearchResult describing the new matches
	 * @throws CancelledException if the user cancels
	 */
	private FidSearchResult makeAllMatches(Function function, HashFamily family,
			ArrayList<HashMatch> culledHashMatches, TaskMonitor monitor) throws CancelledException {
		ArrayList<FidMatch> fidMatches = new ArrayList<FidMatch>();
		for (FidMatchScore hashMatch : culledHashMatches) {
			monitor.checkCanceled();
			FidMatch match = new FidMatchImpl(
				fidQueryService.getLibraryForFunction(hashMatch.getFunctionRecord()),
				function.getEntryPoint(), hashMatch);
			fidMatches.add(match);
		}
		return new FidSearchResult(function, family.getHash(), fidMatches);
	}

	/**
	 * Simply makes a singleton match, since only one function record matched (either outright at
	 * the beginning, or through elimination of less likely possibilities).
	 * @param function the function
	 * @param family is the collection of hashes associated with the function
	 * @param hashMatch the match score
	 * @return a FidSearchResult describing the new match
	 */
	private FidSearchResult makeSingletonMatch(Function function, HashFamily family,
			FidMatchScore hashMatch) {
		final LibraryRecord library =
			fidQueryService.getLibraryForFunction(hashMatch.getFunctionRecord());
		FidMatch match = new FidMatchImpl(library, function.getEntryPoint(), hashMatch);
		return new FidSearchResult(function, family.getHash(), Collections.singletonList(match));
	}

	/**
	 * Generate the hash family around a provided function (used for searching).
	 * @param function the function
	 * @param monitor task monitor to let users cancel
	 * @return the generated hash family
	 * @throws MemoryAccessException if a function body was inexplicably inaccessible
	 * @throws CancelledException
	 */
	private HashFamily getFamily(Function function, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		Address address = function.getEntryPoint();
		FidHashQuad hash = cacheFactory.get(function);
		if (hash == null) {
			return null;
		}
		HashFamily family = new HashFamily(address, hash);
		addChildren(family, function, monitor);
		addParents(family, function, monitor);
		return family;
	}

	/**
	 * Generates a hash mash, and adds its score to the "global" statistics.
	 * @param functionRecord the potential match
	 * @param family the hash family of the function
	 * @param stats global statistics
	 * @param monitor a task monitor
	 * @return the generated hash match
	 * @throws CancelledException if the user cancels
	 */
	private HashMatch scoreMatch(FunctionRecord functionRecord, HashFamily family,
			TaskMonitor monitor) throws CancelledException {
		if (functionRecord.autoFail()) {
			return null;
		}
		int functionCodeUnits = functionRecord.getCodeUnitSize();
		int specificCodeUnits = 0;
		HashLookupListMode mode = HashLookupListMode.FULL;
		if (functionRecord.getSpecificHash() == family.getHash().getSpecificHash()) {
			specificCodeUnits = functionRecord.getSpecificHashAdditionalSize();
			mode = HashLookupListMode.SPECIFIC;
		}

		if (functionRecord.isForceSpecific() && (mode != HashLookupListMode.SPECIFIC)) {
			return null;
		}
		if (functionRecord.autoPass()) {
			if (functionCodeUnits < mediumHashCodeUnitLengthLimit) {
				functionCodeUnits = mediumHashCodeUnitLengthLimit;
			}
		}

		int childCodeUnits = 0;

		for (FidHashQuad fidHashQuad : family.getChildren()) {
			monitor.checkCanceled();
			if (fidQueryService.getSuperiorFullRelation(functionRecord, fidHashQuad)) {
				childCodeUnits += fidHashQuad.getCodeUnitSize();
			}
		}

		if (functionRecord.isForceRelation() && childCodeUnits == 0) {
			return null;
		}

		int parentCodeUnits = 0;

		if (family.getParents().size() < MAX_NUM_PARENTS_FOR_SCORE) {
			for (FidHashQuad fidHashQuad : family.getParents()) {
				monitor.checkCanceled();
				if (fidQueryService.getInferiorFullRelation(fidHashQuad, functionRecord)) {
					parentCodeUnits += fidHashQuad.getCodeUnitSize();
				}
			}
		}

		float functionScore = functionCodeUnits;
		functionScore += 0.67 * specificCodeUnits; // Each specific constant count is worth 2/3 of a whole code unit
		float childScore = childCodeUnits;
		float parentScore = parentCodeUnits;
		if (functionScore + childScore + parentScore < scoreThreshold) {
			return null;
		}

		HashMatch result =
			new HashMatch(functionRecord, functionScore, mode, childScore, parentScore);

		return result;
	}

	/**
	 * Given a hash family, find raw matches in the FID service.
	 * @param family the hash family
	 * @param monitor a task monitor
	 * @return a list of matches
	 * @throws CancelledException if the user cancels
	 */
	private List<HashMatch> lookupFamily(HashFamily family, TaskMonitor monitor)
			throws CancelledException {
		ArrayList<HashMatch> result = new ArrayList<HashMatch>();

		List<FunctionRecord> functionsByFullHash =
			fidQueryService.findFunctionsByFullHash(family.getHash().getFullHash());

		for (FunctionRecord functionRecord : functionsByFullHash) {
			monitor.checkCanceled();
			HashMatch match = scoreMatch(functionRecord, family, monitor);
			if (match != null) {
				result.add(match);
			}
		}

		Collections.sort(result, MOST_SIGNIFICANT);

		return result;
	}

	/**
	 * Search for matches to a single function. Only returns null, if the function can't be hashed.
	 * @param function is the function to search for
	 * @param monitor is a monitor to check for cancels
	 * @return the FidSearchResult object describing any matches (or if there are none)
	 * @throws MemoryAccessException
	 * @throws CancelledException
	 */
	public FidSearchResult searchFunction(Function function, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		HashFamily family = getFamily(function, monitor);
		FidSearchResult fidResult = null;
		if (family != null) {
			fidResult = processMatches(function, family, monitor);
			if (fidResult == null) {
				fidResult = new FidSearchResult(function, family.getHash(), null);
			}
		}
		return fidResult;
	}

	/**
	 * Searches the database for function names.
	 * @param monitor a task monitor
	 * @return the results of all the searching
	 * @throws CancelledException if the user cancels
	 */
	public List<FidSearchResult> search(TaskMonitor monitor) throws CancelledException {
		List<FidSearchResult> result = new LinkedList<FidSearchResult>();

		FunctionManager functionManager = program.getFunctionManager();
		monitor.initialize(functionManager.getFunctionCount());
		FunctionIterator functions = functionManager.getFunctions(true);
		for (Function function : functions) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			try {
				HashFamily family = getFamily(function, monitor);
				if (family != null) {
					FidSearchResult searchResult = processMatches(function, family, monitor);
					if (searchResult != null) {
						result.add(searchResult);
					}
				}
			}
			catch (MemoryAccessException e) {
				Msg.showError(this, null, "Memory Access Exception",
					"Internal error, degenerate unhashable function");
			}
		}

		return result;
	}

}
