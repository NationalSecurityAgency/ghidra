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
import java.util.Map.Entry;

import ghidra.feature.fid.db.LibraryRecord;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;

/**
 * Implementation class for FidPopulateResult.
 */
public class FidPopulateResult {
	/**
	 * The actual state representing what happened to the function.
	 */
	public static enum Disposition {
		// included is the only "positive" state
		INCLUDED,
		// all the following are "negative", as in the function was excluded
		IS_THUNK,
		FAILED_FUNCTION_FILTER,
		FAILS_MINIMUM_SHORTHASH_LENGTH,
		NO_DEFINED_SYMBOL,
		MEMORY_ACCESS_EXCEPTION,
		DUPLICATE_INFO
	}

	private LibraryRecord libraryRecord;
	private LinkedHashMap<Location, Disposition> extremeFailureMap;
	private ArrayList<Location> unresolvedSymbols;
	private List<Count> maxChildRefs;
	private int totalDisposition = 0;
	private int numIncluded = 0;
	private int numThunk = 0;
	private int numFiltered = 0;
	private int numFailedMinimum = 0;
	private int numMemAccess = 0;
	private int numNoDefinedSymbol = 0;
	private int numDuplicates = 0;

	FidPopulateResult(LibraryRecord libraryRecord) {
		this.libraryRecord = libraryRecord;
		unresolvedSymbols = new ArrayList<Location>();
		extremeFailureMap = new LinkedHashMap<Location, Disposition>();
	}

	void disposition(DomainFile domainFile, String functionName, Address functionEntryPoint,
			Disposition disposition) {
		totalDisposition += 1;
		switch (disposition) {
			case FAILED_FUNCTION_FILTER:
				numFiltered += 1;
				return; // Don't put in extreme list
			case FAILS_MINIMUM_SHORTHASH_LENGTH:
				numFailedMinimum += 1;
				return; // Don't put in extreme list
			case INCLUDED:
				numIncluded += 1;
				return; // Don't put in extreme list
			case IS_THUNK:
				numThunk += 1;
				return; // Don't put in extreme list
			case DUPLICATE_INFO:
				numDuplicates += 1;
				return; // Don't put in extreme list
			case MEMORY_ACCESS_EXCEPTION:
				numMemAccess += 1;
				break; // Fall-thru to put in extreme list
			case NO_DEFINED_SYMBOL:
				numNoDefinedSymbol += 1;
				break; // Fall-thru to put in extreme list
			default:
				break;

		}
		extremeFailureMap.put(new Location(domainFile, functionName, functionEntryPoint),
			disposition);
	}

	void addUnresolvedSymbol(String functionName) {
		unresolvedSymbols.add(new Location(null, functionName, null));
	}

	public LibraryRecord getLibraryRecord() {
		return libraryRecord;
	}

	/**
	 * Returns a complete map of locations to dispositions.
	 * @return a complete map of locations to dispositions
	 */
	public Map<Location, Disposition> getResults() {
		return Collections.unmodifiableMap(extremeFailureMap);
	}

	/**
	 * Returns how many functions in total were added to the library.
	 * @return how many functions in total were added to the library
	 */
	public int getTotalAdded() {
		return numIncluded;
	}

	/**
	 * Returns how many functions in total were excluded from the library.
	 * @return how many functions in total were excluded from the library
	 */
	public int getTotalExcluded() {
		return totalDisposition - numIncluded;
	}

	/**
	 * Returns how many functions in total were considered for inclusion.
	 * @return how many functions in total were considered for inclusion
	 */
	public int getTotalAttempted() {
		return totalDisposition;
	}

	/**
	 * Returns a map of failed dispositions to their occurrence counts.
	 * @return a map of failed dispositions to their occurrence counts
	 */
	public Map<Disposition, Integer> getFailures() {
		HashMap<Disposition, Integer> result =
			new HashMap<FidPopulateResult.Disposition, Integer>();
		result.put(Disposition.INCLUDED, numIncluded);
		result.put(Disposition.IS_THUNK, numThunk);
		result.put(Disposition.FAILED_FUNCTION_FILTER, numFiltered);
		result.put(Disposition.FAILS_MINIMUM_SHORTHASH_LENGTH, numFailedMinimum);
		result.put(Disposition.MEMORY_ACCESS_EXCEPTION, numMemAccess);
		result.put(Disposition.NO_DEFINED_SYMBOL, numNoDefinedSymbol);
		result.put(Disposition.DUPLICATE_INFO, numDuplicates);
		return result;
	}

	/**
	 * Returns a list of symbols that could not be resolved in the end.
	 * Note that the domain file and function entry point will be null for all these.
	 * @return a list of symbols that could not be resolved in the end
	 */
	public List<Location> getUnresolvedSymbols() {
		return new ArrayList<Location>(unresolvedSymbols);
	}

	public List<Count> getMaxChildReferences() {
		return maxChildRefs;
	}

	public void addChildReferences(int max, Map<String, Count> childHistogram) {
		TreeSet<Count> resort = new TreeSet<Count>();

		// Resort the histogram on counts
		for (Entry<String, Count> entry : childHistogram.entrySet()) {
			Count count = entry.getValue();
			count.name = entry.getKey();
			resort.add(count);
		}

		maxChildRefs = new LinkedList<Count>();
		int i = 0;
		for (Count count : resort) {
			maxChildRefs.add(count);
			i += 1;
			if (i >= max) {
				break;
			}
		}
	}

	public static class Count implements Comparable<Count> {
		public String name;
		public int count;
		public boolean isVeryCommon;

		@Override
		public int compareTo(Count o) {
			if (count == o.count) {
				return name.compareTo(o.name);
			}
			return (count < o.count) ? 1 : -1; // bigger comes first
		}
	}

}
