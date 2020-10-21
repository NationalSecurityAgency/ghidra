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
	private TreeSet<String> rawNames = null;
	private TreeSet<String> similarBaseNames = null;
	private TreeSet<String> demangledNameNoTemplate = null;
	private TreeSet<String> exactDemangledBaseNames = null;
	private TreeSet<String> libraries = null;
	private boolean demangleSelect = false;		// True if either deamngledNameNoTemplate or exactDemangledBaseNames is unique
	
	private int mostOptimisticCount;			// What is most optimistic (smallest) number of matches
												// Once duplicates and similar base names are taken into account
	private float overallScore = 0.0f;

	public int numNames() {
		return finalNameList.size();
	}

	public boolean isDemangled() {
		return demangleSelect;
	}

	public Iterator<String> getRawNameIterator() {
		return rawNames.iterator();
	}

	public boolean containsRawName(String name) {
		return rawNames.contains(name);
	}

	public Iterator<String> getNameIterator() {
		return finalNameList.iterator();
	}

	public int numSimilarNames() {
		return similarBaseNames.size();
	}

	public int numLibraries() {
		return libraries.size();
	}

	public Iterator<String> getLibraryIterator() {
		return libraries.iterator();
	}

	public int getMostOptimisticCount() {
		return mostOptimisticCount;
	}

	public float getOverallScore() {
		return overallScore;
	}

	public void analyzeNames(List<FidMatch> matches, Program program, TaskMonitor monitor)
				throws CancelledException {

		rawNames = new TreeSet<String>();
		similarBaseNames = new TreeSet<String>();
		demangledNameNoTemplate = new TreeSet<String>();
		exactDemangledBaseNames = new TreeSet<String>();
		int cannotDetemplate = 0;
		int cannotDemangle = 0;

		for (FidMatch match : matches) {
			monitor.checkCanceled();

			FunctionRecord function = match.getFunctionRecord();

			NameVersions nameVersions = NameVersions.generate(function.getName(), program);
			// Put exact base names in a HashSet
			if (nameVersions.rawName != null) {
				rawNames.add(nameVersions.rawName);				// Dedup the raw names
				similarBaseNames.add(nameVersions.similarName);	// Dedup names with underscores removed
				if (nameVersions.demangledNoTemplate != null) {
					demangledNameNoTemplate.add(nameVersions.demangledNoTemplate);
				}
				else {
					cannotDetemplate += 1;
				}
				if (nameVersions.demangledBaseName != null) {
					exactDemangledBaseNames.add(nameVersions.demangledBaseName);		// Dedup demangled base name
				}
				else {
					cannotDemangle += 1;
				}
			}
		}

		String singleName = null;
		mostOptimisticCount = rawNames.size();
		finalNameList = rawNames;
		if (rawNames.size() == 1) {
			singleName = rawNames.first();
		}
		else {
			singleName = findCommonBaseName();
			mostOptimisticCount = similarBaseNames.size();
			if (singleName == null) {
				singleName = findCommonNoTemplate(cannotDetemplate);
				if (singleName != null) {
					demangleSelect = true;
				}
				if (demangledNameNoTemplate.size() > 0 &&
					demangledNameNoTemplate.size() < mostOptimisticCount) {
					mostOptimisticCount = demangledNameNoTemplate.size();
				}
			}
			if (singleName == null) {
				singleName = findCommonDemangledBaseName(cannotDemangle);
				if (singleName != null) {
					demangleSelect = true;
				}
				if (exactDemangledBaseNames.size() > 0 &&
					exactDemangledBaseNames.size() < mostOptimisticCount) {
					mostOptimisticCount = exactDemangledBaseNames.size();
				}
			}
		}
		if (singleName != null) {
			mostOptimisticCount = 1;
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

	private String findCommonBaseName() {
		if (similarBaseNames.size() == 1) {
			return rawNames.iterator().next();
		}
		return null;
	}

	private String findCommonNoTemplate(int cannotDetemplate) {
		if (cannotDetemplate > 0) {
			return null;			// Couldn't remove a parameters from everything, so we can't have a common template
		}
		if (demangledNameNoTemplate.size() == 1) {
			return demangledNameNoTemplate.first();
		}
		return null;
	}

	private String findCommonDemangledBaseName(int cannotDemangle) {
		if (cannotDemangle > 0) {
			return null;			// Couldn't demangle everything, so no way we can have a common base
		}
		if (exactDemangledBaseNames.size() == 1) {
			return exactDemangledBaseNames.first();
		}
		return null;
	}
}
