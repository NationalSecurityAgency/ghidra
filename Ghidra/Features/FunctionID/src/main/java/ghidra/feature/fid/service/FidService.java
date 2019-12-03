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

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;

import generic.hash.FNV1a64MessageDigestFactory;
import generic.hash.MessageDigestFactory;
import generic.stl.Pair;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.hash.*;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.search.InstructionSkipper;
import ghidra.util.task.TaskMonitor;

/** 
 * Implementation of the easy parts of the service; the complicated methods
 * all delegate to *LibraryCreation or *LibrarySearch utility classes
 */
public class FidService {
	// it's possible in the future these shouldn't be hard-coded and
	// instead belong to the library, although that would complicate
	// matters quite a bit in search
	public static final byte SHORT_HASH_CODE_UNIT_LENGTH = 4;
	public static final byte MEDIUM_HASH_CODE_UNIT_LENGTH = 24;
	public static final float SCORE_THRESHOLD = 14.6f;
	public static final float MULTINAME_SCORE_THRESHOLD = 30;

	private FidFileManager fidFileManager;

	private FunctionExtentGenerator generator;
	private MessageDigestFactory digestFactory;
	private HashMap<Processor, List<InstructionSkipper>> skippers;

	public FidService() {
		fidFileManager = FidFileManager.getInstance();
		this.generator = new FunctionBodyFunctionExtentGenerator();
		this.digestFactory = new FNV1a64MessageDigestFactory();
		this.skippers = new HashMap<>();

		List<Class<? extends InstructionSkipper>> classes =
			ClassSearcher.getClasses(InstructionSkipper.class);
		for (Class<? extends InstructionSkipper> clazz : classes) {
			try {
				InstructionSkipper skipper = clazz.newInstance();
				Processor processor = skipper.getApplicableProcessor();
				List<InstructionSkipper> list = skippers.get(processor);
				if (list == null) {
					list = new ArrayList<>();
					skippers.put(processor, list);
				}
				list.add(skipper);
			}
			catch (InstantiationException e) {
				// we tried
			}
			catch (IllegalAccessException e) {
				// we tried
			}
		}
	}

	/**
	 * Returns the length (in code units) of the short hash.
	 * @return the length (in code units) of the short hash
	 */

	public byte getShortHashCodeUnitLength() {
		return SHORT_HASH_CODE_UNIT_LENGTH;
	}

	/**
	 * Returns the length limit (in code units) of the medium hash.
	 * @return the length limit (in code units) of the medium hash
	 */

	public byte getMediumHashCodeUnitLengthLimit() {
		return MEDIUM_HASH_CODE_UNIT_LENGTH;
	}

	/**
	 * @return the default threshold for a code unit score to be considered a match
	 */

	public float getDefaultScoreThreshold() {
		return SCORE_THRESHOLD;
	}

	/**
	 * @return the default codeunit threshold for labeling a function with conflicting matches
	 */

	public float getDefaultMultiNameThreshold() {
		return MULTINAME_SCORE_THRESHOLD;
	}

	/**
	 * Hashes a single function.
	 * @param function the function to hash
	 * @return the small, medium and full hash result
	 * @throws MemoryAccessException if something goes wrong reading bytes in the domain file
	 */

	public FidHashQuad hashFunction(Function function) throws MemoryAccessException {
		List<CodeUnit> codeUnits = generator.calculateExtent(function);
		if (codeUnits.size() < getShortHashCodeUnitLength()) {
			return null;
		}

		FidHasher fidHasher = getHasher(function.getProgram());
		FidHashQuad hashTriple = fidHasher.hash(function);

		return hashTriple;
	}

	/**
	 * Get the FidHasher object suitable for producing FidHashQuad objects for functions coming from
	 * a particular program.
	 * @param program is the Program to configure the hasher for
	 * @return the FidHasher object
	 */

	public FidHasher getHasher(Program program) {
		List<InstructionSkipper> list = skippers.get(program.getLanguage().getProcessor());
		if (list == null) {
			list = Collections.emptyList();
		}
		FidHasher fidHasher =
			new MessageDigestFidHasher(generator, SHORT_HASH_CODE_UNIT_LENGTH, digestFactory, list);
		return fidHasher;
	}

	/**
	 * Return the FidProgramSeeker context object for searching for Fid matches in a specific Program
	 * @param program is the program to configure the seeker for
	 * @param fidQueryService is the set of databases the seeker should query
	 * @param scoreThreshold is the (codeUnit) threshold matches must meet to be reported by the seeker
	 * @return the FidProgramSeeker
	 * @throws IOException 
	 * @throws VersionException 
	 */

	public FidProgramSeeker getProgramSeeker(Program program, FidQueryService fidQueryService,
			float scoreThreshold) throws VersionException, IOException {
		FidHasher fidHasher = getHasher(program);
		FidProgramSeeker seeker = new FidProgramSeeker(fidQueryService, program, fidHasher,
			getShortHashCodeUnitLength(), getMediumHashCodeUnitLengthLimit(), scoreThreshold);
		return seeker;
	}

	/**
	 * Extracts function hashes from a list of programs (domain files) and
	 * puts them into the scratch library.
	 * @param fidDb the database to populate
	 * @param libraryFamilyName the library family name
	 * @param libraryVersion the library version
	 * @param libraryVariant the library variant
	 * @param programDomainFiles the domain files to use when populating the library
	 * @param functionFilter a filter to possibly reject functions from the library
	 * @param languageId the ghidra language id to filter on, or null
	 * @param linkLibraries libraries to search for (internally) unresolved symbols
	 * @param commonSymbols is a list of symbols for which relationships are not generated
	 * @param monitor a task monitor
	 * @throws MemoryAccessException if bytes are unavailable for a function body
	 * @throws VersionException if any program cannot be opened without an upgrade
	 * @throws CancelledException if the user cancels
	 * @throws IOException if something goes wrong reading bytes in the domain file
	 */

	public FidPopulateResult createNewLibraryFromPrograms(FidDB fidDb, String libraryFamilyName,
			String libraryVersion, String libraryVariant, List<DomainFile> programDomainFiles,
			Predicate<Pair<Function, FidHashQuad>> functionFilter, LanguageID languageId,
			List<LibraryRecord> linkLibraries, List<String> commonSymbols, TaskMonitor monitor)
			throws MemoryAccessException, VersionException, CancelledException,
			IllegalStateException, IOException {
		FidServiceLibraryIngest ingest = new FidServiceLibraryIngest(fidDb, this, libraryFamilyName,
			libraryVersion, libraryVariant, programDomainFiles, functionFilter, languageId,
			linkLibraries, monitor);
		ingest.markCommonChildReferences(commonSymbols);
		return ingest.create();
	}

	/**
	 * Searches the database to find results for a program.
	 * @param program the program to process
	 * @param queryService holds the current set of databases to query
	 * @param scoreThreshold is the (codeUnit) threshold matches must meet to be reported
	 * @param monitor a task monitor
	 * @return a list of the FID search results
	 * @throws CancelledException if the user cancels
	 * @throws IOException 
	 * @throws VersionException 
	 */

	public List<FidSearchResult> processProgram(Program program, FidQueryService queryService,
			float scoreThreshold, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		FidProgramSeeker seeker = getProgramSeeker(program, queryService, scoreThreshold);
		List<FidSearchResult> searchResult = seeker.search(monitor);
		return searchResult;
	}

	/**
	 * Mark functions as automatically passing any search
	 * @param funcList is the list of records to modify
	 * @param value is the new value of the auto-pass property
	 * @return a list of records reflecting the change
	 * @throws IOException
	 */

	public List<FunctionRecord> markRecordsAutoPass(List<FunctionRecord> funcList,
			boolean value) throws IOException {
		ArrayList<FunctionRecord> res = new ArrayList<>();
		for (FunctionRecord funcRec : funcList) {
			res.add(funcRec.getFidDb().setAutoPassOnFunction(funcRec, value));
		}
		return res;
	}

	/**
	 * Mark functions as automatically failing any search
	 * @param funcList is the list of records to modify
	 * @param value is the new value of the auto-fail property
	 * @return a list of records reflecting the change
	 * @throws IOException
	 */

	public List<FunctionRecord> markRecordsAutoFail(List<FunctionRecord> funcList,
			boolean value) throws IOException {
		ArrayList<FunctionRecord> res = new ArrayList<>();
		for (FunctionRecord funcRec : funcList) {
			res.add(funcRec.getFidDb().setAutoFailOnFunction(funcRec, value));
		}
		return res;
	}

	/**
	 * Mark functions as requiring any search result to match the specific hash
	 * @param funcList is the list of records to modify
	 * @param value is the new value of the force-specific property
	 * @return a list of records reflecting the change
	 * @throws IOException
	 */

	public List<FunctionRecord> markRecordsForceSpecific(List<FunctionRecord> funcList,
			boolean value) throws IOException {
		ArrayList<FunctionRecord> res = new ArrayList<>();
		for (FunctionRecord funcRec : funcList) {
			res.add(funcRec.getFidDb().setForceSpecificOnFunction(funcRec, value));
		}
		return res;
	}

	/**
	 * Mark functions as requiring any search result to also match one of its child/parents
	 * @param funcList is the list of records to modify
	 * @param value is the new value of the force-relation property
	 * @return a list of records reflecting the change
	 * @throws IOException
	 */

	public List<FunctionRecord> markRecordsForceRelation(List<FunctionRecord> funcList,
			boolean value) throws IOException {
		ArrayList<FunctionRecord> res = new ArrayList<>();
		for (FunctionRecord funcRec : funcList) {
			res.add(funcRec.getFidDb().setForceRelationOnFunction(funcRec, value));
		}
		return res;
	}

	/**
	 * Returns true if at least one FidLibraryDatabases can process programs with the given language
	 * @param language the language to test Fid Databases for
	 * @return true if at least one FidLibraryDatabases can process programs with the given language
	 */

	public boolean canProcess(Language language) {
		return fidFileManager.canQuery(language);
	}

	/**
	 * Creates a new FidQueryService that can facilitate performing a query over multiple
	 * Fid databases. This causes the appropriate databases to be opened, and therefore, the
	 * caller of this method is responsible for closing the FidQueryService when done with it.
	 * @param language the language that will be queried against
	 * @param openForUpdate if true, the databases will be opened for read/write.  Otherwise
	 * it will be opened for reading only.
	 * @return a new FidQueryService that allows querying across all appropriate fid databases for the given language.
	 * @throws VersionException
	 * @throws IOException
	 */

	public FidQueryService openFidQueryService(Language language, boolean openForUpdate)
			throws VersionException, IOException {
		return fidFileManager.openFidQueryService(language, openForUpdate);
	}
}
