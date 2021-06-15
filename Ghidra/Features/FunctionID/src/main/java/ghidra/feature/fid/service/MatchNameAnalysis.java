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

import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyze all the FID matches for a single function to determine what results are returned.
 * Consider matches with the same name from different libraries, and matches with the same base name.
 *
 */
public class MatchNameAnalysis {
	private Set<String> finalNameList = null;
	private TreeMap<String, NameVersions> versionMap = null;
	private TreeSet<String> rawNames = null;
	private TreeSet<String> similarBaseNames = null;
	private TreeSet<String> demangledNameNoTemplate = null;
	private TreeSet<String> exactDemangledBaseNames = null;
	private TreeSet<String> libraries = null;
	
	private float overallScore = 0.0f;

	/**
	 * @return the number of deduped symbol names
	 */
	public int numNames() {
		return finalNameList.size();
	}

	/**
	 * @return an iterator to the deduped list of raw names (similar names are not collapsed)
	 */
	public Iterator<String> getRawNameIterator() {
		return rawNames.iterator();
	}

	/**
	 * Check if the given name is contained in the list of matches
	 * @param name is the given name
	 * @return true if the name is in the list
	 */
	public boolean containsRawName(String name) {
		return rawNames.contains(name);
	}

	/**
	 * @return an iterator to the final list of deduped symbol names
	 */
	public Iterator<String> getNameIterator() {
		return finalNameList.iterator();
	}

	/**
	 * @return the number of symbols in the deduped list of matching libraries
	 */
	public int numLibraries() {
		return libraries.size();
	}

	/**
	 * @return an iterator to the deduped list of matching libraries
	 */
	public Iterator<String> getLibraryIterator() {
		return libraries.iterator();
	}

	/**
	 * Get an object with all the given versions of the given raw name
	 * @param raw is the raw name
	 * @return the corresponding NameVersions object
	 */
	public NameVersions getVersions(String raw) {
		return versionMap.get(raw);
	}

	/**
	 * Run through all deduping strategies and return the number of unique symbols given
	 * by the best strategy.
	 * @return number of unique symbols given by the optimal deduping strategy
	 */
	public int getMostOptimisticCount() {
		int count = rawNames.size();
		if (similarBaseNames.size() < count) {
			count = similarBaseNames.size();
		}
		if (demangledNameNoTemplate != null && demangledNameNoTemplate.size() < count) {
			count = demangledNameNoTemplate.size();
		}
		if (exactDemangledBaseNames != null && exactDemangledBaseNames.size() < count) {
			count = exactDemangledBaseNames.size();
		}
		return count;
	}

	/**
	 * Run through ALL deduping strategies and if one results in a single label, return that label.
	 * Otherwise return null.
	 * @return a unique name describing all matches or null
	 */
	public String getMostOptimisticName() {
		if (rawNames.size() == 1) {
			return rawNames.first();
		}
		if (similarBaseNames.size() == 1) {
			return similarBaseNames.first();
		}
		if (demangledNameNoTemplate != null && demangledNameNoTemplate.size() == 1) {
			return demangledNameNoTemplate.first();
		}
		if (exactDemangledBaseNames != null && exactDemangledBaseNames.size() == 1) {
			return exactDemangledBaseNames.first();
		}
		return null;
	}

	public float getOverallScore() {
		return overallScore;
	}

	/**
	 * Analyze a list of FID matches from a single address, deciding on the final list of symbols
	 * that will be associated with the address by deduping and omitting similar names.
	 * The final list is in finalNameList.
	 * Demangling and template stripping can produce an even shorter list than finalNameList.
	 * This is optionally available through getMostOptimisticName().
	 * @param matches is the set of FID matches to analyze
	 * @param program is the Program
	 * @param monitor is the monitor
	 * @throws CancelledException if the user cancels the task
	 */
	public void analyzeNames(List<FidMatch> matches, Program program, TaskMonitor monitor)
				throws CancelledException {

		versionMap = new TreeMap<String, NameVersions>();
		rawNames = new TreeSet<String>();
		similarBaseNames = new TreeSet<String>();
		demangledNameNoTemplate = new TreeSet<String>();
		exactDemangledBaseNames = new TreeSet<String>();

		for (FidMatch match : matches) {
			monitor.checkCanceled();

			FunctionRecord function = match.getFunctionRecord();

			NameVersions nameVersions = NameVersions.generate(function.getName(), program);
			// Put exact base names in a HashSet
			if (nameVersions.rawName != null) {
				versionMap.put(nameVersions.rawName, nameVersions);
				rawNames.add(nameVersions.rawName);				// Dedup the raw names
				similarBaseNames.add(nameVersions.similarName);	// Dedup names with underscores removed
				if (nameVersions.demangledNoTemplate != null && demangledNameNoTemplate != null) {
					demangledNameNoTemplate.add(nameVersions.demangledNoTemplate);
				}
				else {
					demangledNameNoTemplate = null;		// Get rid of container if we can't strip everything
				}
				if (nameVersions.demangledBaseName != null && exactDemangledBaseNames != null) {
					exactDemangledBaseNames.add(nameVersions.demangledBaseName);		// Dedup demangled base name
				}
				else {
					exactDemangledBaseNames = null;		// Get rid of container if we can't demangle everything
				}
			}
		}

		finalNameList = rawNames;
		String singleName = findCommonBaseName();
		if (singleName != null) {
			finalNameList = Collections.singleton(singleName);
		}
		else if (rawNames.size() > similarBaseNames.size()) {
			// if names are the same except for underscores use the similar name
			// list to remove dupes
			finalNameList = similarBaseNames;
		}

		if (matches.size() > 0) {
			overallScore = matches.get(0).getOverallScore();
		}
	}
	
	/**
	 * Collect strings describing the library descriptor of a set of FID matches.
	 * Dedup the list trying to get the size down below a specified limit, stripping
	 * version and family information from the library string if necessary.
	 * @param matches is the set of FID matches
	 * @param libraryLimit is the specified size limit
	 * @param monitor is a task monitor
	 * @throws CancelledException if the user cancels the task
	 */
	public void analyzeLibraries(Collection<FidMatch> matches,int libraryLimit,TaskMonitor monitor)
			throws CancelledException {
		libraries = new TreeSet<String>();

		for (FidMatch match : matches) {
			// Put libraries in a HashSet
			String library = match.getLibraryRecord().toString();
			if (library != null) {
				libraries.add(library);
			}
			if (libraries.size() >= libraryLimit) {
				break;
			}
		}
		if (libraries.size() >= libraryLimit) {		// Too many libraries to directly display
			// Try getting rid of the variant field, to see if we can reduce the count
			libraries.clear();
			for (FidMatch match : matches) {
				monitor.checkCanceled();

				LibraryRecord libraryRecord = match.getLibraryRecord();
				String familyVersion =
					libraryRecord.getLibraryFamilyName() + " " + libraryRecord.getLibraryVersion();
				libraries.add(familyVersion);
				if (libraries.size() >= libraryLimit) {
					break;		// Don't bother trying to add any more, there are too many
				}
			}
		}
		if (libraries.size() >= libraryLimit) {		// Still too many libraries
			// Try just listing the library family
			libraries.clear();
			for (FidMatch match : matches) {
				monitor.checkCanceled();

				LibraryRecord libraryRecord = match.getLibraryRecord();
				String familyVersion = libraryRecord.getLibraryFamilyName();
				libraries.add(familyVersion);
			}
		}
	}

	/**
	 * Make a final decision based on the deduping strategies if there is a single
	 * matching name that describes all matches.
	 * @return the single matching name or null
	 */
	private String findCommonBaseName() {
		if (rawNames.size() == 1 || similarBaseNames.size() == 1) {
			return rawNames.first();
		}
		return null;
	}
}
