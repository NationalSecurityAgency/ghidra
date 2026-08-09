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
package ghidra.feature.fid.db;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.sourcelanguage.SourceLanguageID;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;

/**
 * A filter on programs that are either being ingested into or queried against
 * a single FID database file. 
 */
public class FidFilter {
	private TreeMap<LanguageID, Set<CompilerSpecID>> languages;
	private Set<SourceLanguageID> sources;

	/**
	 * Create a set of CompilerSpecID from a list of names.
	 * A null or empty string means create a set that matches all compiler specs,
	 * which is returned as an empty set.
	 * @param rawString is a comma separated list of compiler spec names
	 * @return the set of CompilerSpecID
	 */
	private static Set<CompilerSpecID> buildCompilerSpecIDSet(String rawString) {
		if (rawString == null) {
			return new HashSet<>();
		}
		String[] ids = rawString.split("[ ,]+");
		Set<CompilerSpecID> idSet = Arrays.stream(ids)
				.filter(s -> !s.isEmpty())
				.map(CompilerSpecID::new)
				.collect(Collectors.toSet());
		return idSet;
	}

	/**
	 * Create a set of SourceLanguageID from a list of names.
	 * A null or empty string means create a set that matches all source languages,
	 * which is returned null.
	 * @param rawString is a comma separated list of source language names
	 * @return the set of SourceLanguageID
	 */
	private static Set<SourceLanguageID> buildSourceLanguageIDSet(String rawString) {
		if (rawString == null) {
			return null;
		}
		String[] ids = rawString.split("[ ,]+");
		Set<SourceLanguageID> idSet = Arrays.stream(ids)
				.filter(s -> !s.isEmpty())
				.map(SourceLanguageID::new)
				.collect(Collectors.toSet());
		if (idSet.isEmpty()) {
			return null;
		}
		return idSet;
	}

	/**
	 * Add the program properties used to create the given library to this filter.
	 * @param record is the given library
	 */
	private void addLibrary(LibraryRecord record) {
		Set<SourceLanguageID> sourceSet =
			buildSourceLanguageIDSet(record.getGhidraSourceLanguageID());
		if (sources != null) {
			if (sourceSet != null) {
				sources.addAll(sourceSet);
			}
			else {
				sources = null;		// All source languages are supported
			}
		}
		LanguageID languageID = record.getGhidraLanguageID();
		Set<CompilerSpecID> compilerSet =
			buildCompilerSpecIDSet(record.getGhidraCompilerSpecID());
		Set<CompilerSpecID> origSet = languages.get(languageID);
		if (origSet != null) {
			if (!origSet.isEmpty()) {		// Empty indicates all specs allowed (dont modify)
				if (compilerSet == null) {	// NULL indicates library allows all specs
					origSet.clear();
				}
				else {
					origSet.addAll(compilerSet);
				}
			}
		}
		else {
			if (compilerSet == null) {		// NULL indicates library allows all specs
				compilerSet = new HashSet<>();	// Empty indicates all specs allowed
			}
			languages.put(languageID, compilerSet);
		}
	}

	/**
	 * Construct a filter that matches no programs
	 */
	public FidFilter() {
		languages = new TreeMap<>(new ProcessorSizeComparator());
		sources = null;
	}

	/**
	 * Construct a filter that matches programs described by the given FID database
	 * @param fidDB is the database
	 */
	public FidFilter(FidDB fidDB) {
		languages = new TreeMap<>(new ProcessorSizeComparator());
		sources = new HashSet<>();
		List<LibraryRecord> allLibraries = fidDB.getAllLibraries();
		for (LibraryRecord libraryRecord : allLibraries) {
			addLibrary(libraryRecord);
		}
	}

	/**
	 * Construct a filter from ID strings.
	 * A null compilerSpecs means that all compiler specs will pass.
	 * A null sourceLanguages means that all source languages will pass.
	 * @param langID is the language ID as a string
	 * @param compilerSpecs is a comma separated list of compiler specs (or null)
	 * @param sourceLanguages is a comma separated list of source languages (or null)
	 */
	public FidFilter(String langID, String compilerSpecs, String sourceLanguages) {
		languages = new TreeMap<>(new ProcessorSizeComparator());
		LanguageID languageID = new LanguageID(langID);
		Set<CompilerSpecID> compilerSet = buildCompilerSpecIDSet(compilerSpecs);
		languages.put(languageID, compilerSet);
		sources = buildSourceLanguageIDSet(sourceLanguages);
	}

	/**
	 * Test if a program with specific properties passes this filter
	 * @param programID the program properties
	 * @return true if the program passes this filter
	 */
	public boolean test(FidProgramID programID) {
		if (programID.language == null) {
			return true;		// Match everything
		}
		if (sources != null && programID.sources != null) {
			boolean match = false;
			for (SourceLanguageID id : programID.sources) {
				if (sources.contains(id)) {
					match = true;
					break;
				}
			}
			if (!match) {								// There must be at least one match
				return false;
			}
		}
		Set<CompilerSpecID> specsSet = languages.get(programID.language);
		if (specsSet == null) {
			return false;
		}
		if (specsSet.isEmpty()) {
			return true;		// An empty set here means all compiler specs are supported
		}
		if (programID.compiler == null) {
			return true;		// Apply this file even if compiler spec doesn't match
		}
		return specsSet.contains(programID.compiler);
	}

	/**
	 * Test if a program passes this filter
	 * @param program the program
	 * @return true if the program passes this filter
	 */
	public boolean test(Program program) {
		return test(new FidProgramID(program, false));
	}

	/**
	 * If this filters on a single LanguageID, return it. Return null otherwise.
	 * @return the single LanguageID or null
	 */
	public LanguageID getLanguageID() {
		if (languages.size() != 1) {
			return null;
		}
		return languages.firstKey();
	}

	/**
	 * Build a string of comma separated compiler spec names associated with the given language
	 * @param lang is the given language
	 * @return the string
	 */
	public String getCompilerSpecString(LanguageID lang) {
		String compilerString = "";
		Set<CompilerSpecID> compilerSet = languages.get(lang);
		if (compilerSet != null && !compilerSet.isEmpty()) {
			compilerString = compilerSet.stream()
					.sorted()
					.map(CompilerSpecID::getIdAsString)
					.collect(Collectors.joining(","));
		}
		return compilerString;
	}

	/**
	 * Get set of compiler specs that pass for the given language
	 * @param lang is the given language
	 * @return the set or null if the language doesn't pass this filter
	 */
	public Set<CompilerSpecID> getCompilerSpecs(LanguageID lang) {
		return languages.get(lang);
	}

	/**
	 * Build a string of comma separated source language names associated with this
	 * @return the string
	 */
	public String getSourceLanguageString() {
		String sourceString = "";
		if (sources != null && !sources.isEmpty()) {
			sourceString = sources.stream()
					.sorted()
					.map(SourceLanguageID::getIdAsString)
					.collect(Collectors.joining(","));
		}
		return sourceString;
	}

	/**
	 *  Comparator for deciding if a target language "matches" an architecture for a library
	 *  We want processor family, endianness and "size" to match, but variant can be different
	 */
	private static class ProcessorSizeComparator implements Comparator<LanguageID> {

		@Override
		public int compare(LanguageID o1, LanguageID o2) {
			int o1pos = o1.getIdAsString().lastIndexOf(':');
			int o2pos = o2.getIdAsString().lastIndexOf(':');
			if (o1pos >= 0 && o2pos >= 0) {
				String o1Front = o1.getIdAsString().substring(0, o1pos);
				String o2Front = o2.getIdAsString().substring(0, o2pos);
				return o1Front.compareTo(o2Front);
			}
			if (o1pos >= 0) {
				return 1;
			}
			if (o2pos >= 0) {
				return -1;
			}
			return o1.getIdAsString().compareTo(o2.getIdAsString());
		}

	}
}
