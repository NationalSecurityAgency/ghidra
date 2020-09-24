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
	private TreeSet<String> exactDemangledBaseNames = null;
	private TreeSet<String> libraries = null;
	
	private int mostOptimisticCount;			// What is most optimistic (smallest) number of matches
												// Once duplicates and similar base names are taken into account
	private float overallScore = 0.0f;

	public int numNames() {
		return finalNameList.size();
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
		exactDemangledBaseNames = new TreeSet<String>();
		int cannotDemangle = 0;

		for (FidMatch match : matches) {
			monitor.checkCanceled();

			FunctionRecord function = match.getFunctionRecord();

			NameVersions nameVersions = NameVersions.generate(function.getName(), program);
			// Put exact base names in a HashSet
			if (nameVersions.rawName != null) {
				rawNames.add(nameVersions.rawName);				// Dedup the raw names
				similarBaseNames.add(nameVersions.similarName);	// Dedup names with underscores removed
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
				singleName = findCommonDemangledBaseName(cannotDemangle);
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

	/**
	 * If there exists an initial set of template parameters bracketed by '<' and '>'
	 * in this name, strip them from the name.
	 * @param name is the function name to strip
	 * @return the stripped name or null if no parameters present
	 */
	public static String removeTemplateParams(String name) {
		int pos1 = name.indexOf('<');
		if (pos1 < 0) {
			return null;
		}
		int nesting = 1;
		int pos2;
		for (pos2 = pos1 + 1; pos2 < name.length(); ++pos2) {
			char c = name.charAt(pos2);
			if (c == '<') {
				nesting += 1;
			}
			else if (c == '>') {
				nesting -= 1;
				if (nesting == 0) {
					break;
				}
			}
		}
		if (nesting != 0) {
			return null;
		}
		return name.substring(0, pos1 + 1) + name.substring(pos2);
	}

	private String findCommonDemangledBaseName(int cannotDemangle) {
		if (cannotDemangle > 0) {
			return null;			// Couldn't demangle everything, so no way we can have a common base
		}
		if (exactDemangledBaseNames.size() == 1) {
			return exactDemangledBaseNames.iterator().next();
		}
		// If we don't have a unique demangled name, try excising template parameters
		String finalName = null;
		for (String name : exactDemangledBaseNames) {
			String templateFree = removeTemplateParams(name);
			if (templateFree == null) {
				return null;		// At least one name has no template parameters
			}
			if (finalName == null) {
				finalName = templateFree;
			}
			else if (!finalName.equals(templateFree)) {
				return null;
			}
		}
		return finalName;
	}
}
