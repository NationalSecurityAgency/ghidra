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
package ghidra.app.plugin.core.string;

import java.io.IOException;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.string.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class StringsAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "ASCII Strings";
	private static final String DESCRIPTION =
		"This analyzer searches for valid ASCII strings and automatically creates them in the binary.";

	// Option Names
	private static final String MODELFILE_OPTION_NAME = "Model File";
	private static final String MODELFILE_OPTION_DESCRIPTION =
		"Any model files for this analyzer should be located in the " +
			"Ghidra/Features/Base/data/stringngrams directory and end in \".sng\".";

	private static final String FORCE_MODEL_RELOAD_OPTION_NAME = "Force Model Reload";
	private static final String FORCE_MODEL_RELOAD_OPTION_DESCRIPTION =
		"When checked, forces reload of model files every time the analyzer is run. When unchecked, " +
			"model files will only be reloaded when Ghidra is restarted or when model file option " +
			"name is changed.";

	private static final String MINIMUM_STRING_LENGTH_OPTION_NAME = "Minimum String Length";
	private static final String MINIMUM_STRING_LENGTH_OPTION_DESCRIPTION =
		"The smallest number of characters in a string to be considered a valid string. " +
			"(Smaller numbers will give more false positives). String length must be 4 " +
			"or greater.";

	private static final String REQUIRE_NULL_TERMINATION_OPTION_NAME =
		"Require Null Termination for String";
	private static final String REQUIRE_NULL_TERMINATION_OPTION_DESCRIPTION =
		"If set to true, requires all strings to end in null.";

	private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME =
		"Create Strings Containing References";
	private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESCRIPTION =
		"If checked, allows a string that contains, but does not start with, one or more references" +
			" to be created.";

	private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME =
		"Create Strings Containing Existing Strings";
	private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESCRIPTION =
		"If checked, allows a string to be created even if it contains existing strings (existing " +
			"strings will be cleared). The string will be created only if existing strings (a) " +
			"are wholly contained within the potential string, (b) do not share the same starting " +
			"address as the potential string, (c) share the same ending address as the potential " +
			"string, and (d) are the same datatype as the potential string.";

	private static final String START_ALIGNMENT_OPTION_NAME = "String Start Alignment";
	private static final String START_ALIGNMENT_OPTION_DESCRIPTION =
		"Specifies an alignment requirement for the start of the string. An alignment of 1 " +
			"means the string can start at any address.  An alignment of 2 means the string " +
			"must start on an even address and so on.  Only allowed values are 1,2, and 4.";

	private static final String END_ALIGNMENT_OPTION_NAME = "String end alignment";
	private static final String END_ALIGNMENT_OPTION_DESCRIPTION =
		"Specifies an alignment requirement for the end of the string. An alignment of 1 " +
			"means the string can end at any address. Alignments greater than 1 require that " +
			"(a) the 'require null termination' option be enabled, and (b) if the null-terminated " +
			"string does not end at an aligned boundary, that there exist enough trailing '0' " +
			"bytes following the string to allow alignment. If neither (a) nor (b) apply, end " +
			"alignment is not enforced.";

	private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME =
		"Search Only in Accessible Memory Blocks";
	private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESCRIPTION =
		"If checked, this " +
			"analyzer only searches in memory blocks that have at least one of the Read (R), Write " +
			"(W), or Execute (X) permissions set to true. Enabling this option ensures that strings " +
			"are not created in areas such as overlays or debug sections.";

	// Default Values	
	private static final String MODEL_DEFAULT_NAME = "StringModel.sng";
	private static final boolean FORCE_MODEL_RELOAD_DEFAULT_VALUE = false;
	private static final boolean REQUIRE_NULL_TERMINATION_DEFAULT_VALUE = true;
	private static final boolean ALL_CHAR_WIDTHS_DEFAULT_VALUE = false;
	private static final boolean ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT = true;
	private static final boolean ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT = true;
	private static final boolean SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT = true;

	public static enum Alignment {
		ALIGN_1(1), ALIGN_2(2), ALIGN_4(4);
		private int alignment;

		Alignment(int alignment) {
			this.alignment = alignment;
		}

		public int getAlignment() {
			return alignment;
		}
	}

	public static enum MinStringLen {
		LEN_4(4),
		LEN_5(5),
		LEN_6(6),
		LEN_7(7),
		LEN_8(8),
		LEN_9(9),
		LEN_10(10),
		LEN_11(11),
		LEN_12(12),
		LEN_13(13),
		LEN_14(14),
		LEN_15(15),
		LEN_16(16),
		LEN_17(17),
		LEN_18(18),
		LEN_19(19),
		LEN_20(20),
		LEN_21(21),
		LEN_22(22),
		LEN_23(23),
		LEN_24(24),
		LEN_25(25);

		private int minLength;

		MinStringLen(int minLength) {
			this.minLength = minLength;
		}

		public int getMinLength() {
			return minLength;
		}
	}

	private static Alignment[] alignmentChoices =
		new Alignment[] { Alignment.ALIGN_1, Alignment.ALIGN_2, Alignment.ALIGN_4 };
	private static Alignment START_ALIGNMENT_DEFAULT_VALUE = Alignment.ALIGN_1;
	private static int END_ALIGNMENT_DEFAULT_VALUE = 4;
	private static final MinStringLen MINIMUM_STRING_LENGTH_DEFAULT_VALUE = MinStringLen.LEN_5;

	private static final int ABSOLUTE_MIN_STR_LENGTH = NGramUtils.getMinimumStringLength();

	private String modelName = MODEL_DEFAULT_NAME;
	private boolean forceModelReload = FORCE_MODEL_RELOAD_DEFAULT_VALUE;
	private int minStringLength = MINIMUM_STRING_LENGTH_DEFAULT_VALUE.getMinLength();
	private boolean requireNullEnd = REQUIRE_NULL_TERMINATION_DEFAULT_VALUE;
	private int startAlignment = START_ALIGNMENT_DEFAULT_VALUE.getAlignment();
	private int endAlignment = END_ALIGNMENT_DEFAULT_VALUE;
	private boolean allowStringCreationWithOffcutReferences =
		ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT;
	private boolean allowStringCreationWithExistringSubstring =
		ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT;
	private boolean searchOnlyAccessibleMemBlocks = SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT;

	// Currently not available to user, since we can only process ASCII
	private boolean allCharWidths = ALL_CHAR_WIDTHS_DEFAULT_VALUE;

	private String trigramFile = "StringModel.sng";
	private boolean isLowerCaseModel = false;

	// TODO
	private CodeUnitIterator instructionIterator;
	private CodeUnitIterator definedDataIterator;
	private CodeUnit currInstrCU, currDataCU;
	private Address instrStart, instrEnd, dataStart, dataEnd;

	public StringsAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		// As long as it has memory blocks defined, we can analyze
		return program.getMinAddress() != null;
	}

	void setCreateStringOverExistingString(boolean b) {
		allowStringCreationWithExistringSubstring = b;
	}

	void setCreateStringOverExistingReference(boolean b) {
		allowStringCreationWithOffcutReferences = b;
	}

	void setMinStringLength(int length) {
		minStringLength = length;
	}

	void setRequireNullTermination(boolean b) {
		requireNullEnd = b;
	}

	void setStringStartAlignment(int alignment) {
		boolean validChoice = false;

		for (Alignment choice : alignmentChoices) {
			if (choice.getAlignment() == alignment) {
				validChoice = true;
				break;
			}
		}

		if (validChoice) {
			startAlignment = alignment;
		}
		else {
			Msg.error(this,
				"'" + alignment +
					" is not a valid string start alignment! Setting alignment to default of " +
					START_ALIGNMENT_DEFAULT_VALUE.getAlignment());

			startAlignment = START_ALIGNMENT_DEFAULT_VALUE.getAlignment();
		}
	}

	/**
	 * Set the model name that indicates which string n-grams model to use.
	 * The ".sng" extension is assumed and may be left off.
	 * 
	 * @param name the model name
	 */
	void setModelName(String name) {
		modelName = name;
		setTrigramFileName(modelName);
	}

	/**
	 * Set the parameter to force model reload next time the Strings Analyzer is run.
	 * 
	 * @param b true to force reload
	 */
	void setForceModelReload(boolean b) {
		forceModelReload = b;
	}

	/**
	 * Set the parameter that determines the end-of-string alignment.
	 * 
	 * @param alignment the alignment
	 */
	void setStringEndAlignment(int alignment) {
		endAlignment = (alignment <= 0) ? 1 : alignment;
	}

	/**
	 * Set the parameter that determines whether to search for strings in all memory blocks, or
	 * in blocks where at least one of the R, W, or X permissions are set.
	 *  
	 * @param b  true to only search accessible memory blocks, false to search all memory blocks
	 */
	void setSearchAccessibleMemoryBlocks(boolean b) {
		searchOnlyAccessibleMemBlocks = b;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AddressFactory factory = program.getAddressFactory();
		AddressSpace[] addressSpaces = factory.getAddressSpaces();

		AddressSetView initializedMemory = program.getMemory().getLoadedAndInitializedAddressSet();

		try {

			NGramUtils.startNewSession(trigramFile, forceModelReload);

			isLowerCaseModel = NGramUtils.isLowerCaseModel();

			if (set == null) {
				set = new AddressSet(initializedMemory);
			}

			AddressSet searchSet = initializedMemory.intersect(set);

			if (searchOnlyAccessibleMemBlocks) {

				// Intersect current AddressSet with accessible memory blocks
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				AddressSet memoryBlockAddresses = getMemoryBlockAddresses(blocks);
				searchSet = searchSet.intersect(memoryBlockAddresses);
			}

			for (AddressSpace space : addressSpaces) {

				monitor.checkCanceled();

				// Portion of current address space that intersects with initialized memory
				AddressSet intersecting =
					searchSet.intersectRange(space.getMinAddress(), space.getMaxAddress());

				// Initialize, because we don't want to use the same iterators or
				// code units when we change address spaces
				instructionIterator = null;
				definedDataIterator = null;
				currInstrCU = null;
				currDataCU = null;

				findStrings(program, intersecting, minStringLength, startAlignment, requireNullEnd,
					allCharWidths, monitor);
			}
		}
		catch (IOException e) {
			String msg =
				"Error accessing string model file: " + trigramFile + ": " + e.getMessage();
			log.appendMsg(msg);
			log.setStatus(msg);
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception during string analysis", e);
			log.setStatus("Unexpected exception during string analysis (see console)");
			return false;
		}

		return true;
	}

	private AddressSet getMemoryBlockAddresses(MemoryBlock[] blocks) {

		AddressSet addresses = new AddressSet();
		for (MemoryBlock memBlock : blocks) {
			if (memBlock.getPermissions() > 0) {
				addresses = addresses.union(new AddressSet(memBlock.getStart(), memBlock.getEnd()));
			}
		}
		return addresses;
	}

	/**
	 * Takes a FoundString, determines if it is a "valid" sequence of ASCII characters or not
	 * (determined by the model).  If so, the string is created if the following criteria are
	 * met:
	 * 		- The string does not overlap existing instructions
	 * 		- The exact string doesn't already exist
	 * 		- Any existing defined data within the potential string is:
	 * 			- wholly contained within the potential string
	 * 			- does not share the same starting address as the potential string
	 * 			- shares the same ending address as the potential string
	 * 			- has the same datatype as the potential string
	 * 		  Note: existing data will be cleared when the string is created
	 * 
	 * @param foundString  A string identified by the StringSearcher
	 * @param program  the current program
	 * @param addressSet the addresses to check for conflicts
	 * @param monitor the task monitor
	 * @throws CancelledException 
	 */
	private void createStringIfValid(FoundString foundString, Program program,
			AddressSetView addressSet, TaskMonitor monitor) {

		if (monitor.isCancelled()) {
			return;
		}

		Memory memory = program.getMemory();
		StringAndScores candidate =
			new StringAndScores(foundString.getString(memory), isLowerCaseModel);

		int scoredLength = candidate.getScoredStringLength();
		if (scoredLength < ABSOLUTE_MIN_STR_LENGTH) {
			return;
		}

		NGramUtils.scoreString(candidate);

		if (!candidate.isScoreAboveThreshold()) {
			return;
		}

		Address start = foundString.getAddress();
		Address end = foundString.getEndAddress();

		DataType dataType = foundString.getDataType();
		Listing listing = program.getListing();
		if (!DataUtilities.isUndefinedRange(program, start, end)) {
			if (allowStringCreationWithExistringSubstring) {
				// Check for single string with a common end address which be consumed
				Data definedData = listing.getDefinedDataContaining(end);
				if (definedData == null || definedData.getAddress().compareTo(start) <= 0 ||
					!dataType.isEquivalent(definedData.getDataType()) ||
					!DataUtilities.isUndefinedRange(program, start,
						definedData.getAddress().previous())) {
					return; // conflict data can not be consumed
				}
			}
			else {
				return; // data conflict
			}
		}

		boolean hasOffcutReferences = false;
		if (!allowStringCreationWithOffcutReferences) {
			hasOffcutReferences = hasOffcut(start, end, program);
		}

		// Only make a string if no offcut references or there are offcut references, 
		// but user says so
		if (hasOffcutReferences && !allowStringCreationWithOffcutReferences) {
			return;
		}

		try {

			int length = foundString.getLength();

			if (requireNullEnd && endAlignment > 1) {
				int padLength = getStringPadLength(program, end);

				// Check to make sure extra padding doesn't go over memory
				// boundaries or allow writing over defined data/instructions
				if (padLength > 0) {
					length += getValidPadLength(program, end, padLength);
				}
			}

			// Need to pass length into command for when (requireNullEnd == false).
			// Using the CreateDataCmd (which doesn't allow you to pass in a length)
			// creates a string at the starting address up to the length of the next
			// "00".
			DataUtilities.createData(program, start, foundString.getDataType(), length, false,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

			Msg.trace(this, "Created string '" + candidate.getOriginalString() + "' at " + start);

			monitor.setMessage("Creating String at " + start);
		}
		catch (Exception e) {
			throw new AssertException("Unexpected exception", e);
		}
	}

	/**
	 * Get number of zeros needed to pad the string to the specified alignment.
	 */
	private int getStringPadLength(Program program, Address endAddress) {

		Address nextAddr = endAddress.next();
		if (nextAddr == null) {
			return 0;
		}

		long modResult = nextAddr.getOffset() % endAlignment;
		if (modResult == 0) {
			return 0;
		}

		int padBytesNeeded = endAlignment - (int) modResult;
		try {
			byte[] bytes = new byte[padBytesNeeded];
			if (program.getMemory().getBytes(nextAddr, bytes) == padBytesNeeded) {

				for (byte b : bytes) {
					if (b != 0) {
						return 0;
					}
				}
			}
		}
		catch (Exception e) {
			return 0;
		}

		return padBytesNeeded;
	}

	/**
	 * Verify that adding padding bytes won't violate boundaries or allow defined data
	 * or instructions to be overwritten.
	 * 
	 * @param program		current program
	 * @param stringEndAddress	strings' end address
	 * @param padLength		number of pad bytes
	 * @return	actual number of pad bytes to add to the string
	 */
	private int getValidPadLength(Program program, Address stringEndAddress, int padLength) {

		Listing listing = program.getListing();
		Address address = stringEndAddress;

		for (int i = 0; i < padLength; i++) {
			address = address.next();
			if (address == null) {
				return 0;
			}
			CodeUnit cu = listing.getCodeUnitContaining(address);
			if (cu == null) {
				return 0; // null implies there cannot be data here
			}

			if (!(cu instanceof Data) || ((Data) cu).isDefined()) {
				return 0;
			}
		}

		return padLength;
	}

	private boolean hasOffcut(Address startAddress, Address endAddress, Program program) {

		Address currentAddress = startAddress.next();
		while (currentAddress != null && currentAddress.compareTo(endAddress) <= 0) {

			if (program.getReferenceManager().hasReferencesTo(currentAddress)) {
				return true;
			}

			currentAddress = currentAddress.next();
		}

		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		options.registerOption(MODELFILE_OPTION_NAME, MODEL_DEFAULT_NAME, null,
			MODELFILE_OPTION_DESCRIPTION);

		options.registerOption(MINIMUM_STRING_LENGTH_OPTION_NAME,
			MINIMUM_STRING_LENGTH_DEFAULT_VALUE, null, MINIMUM_STRING_LENGTH_OPTION_DESCRIPTION);

		options.registerOption(REQUIRE_NULL_TERMINATION_OPTION_NAME,
			REQUIRE_NULL_TERMINATION_DEFAULT_VALUE, null,
			REQUIRE_NULL_TERMINATION_OPTION_DESCRIPTION);

		options.registerOption(START_ALIGNMENT_OPTION_NAME, START_ALIGNMENT_DEFAULT_VALUE, null,
			START_ALIGNMENT_OPTION_DESCRIPTION);

		options.registerOption(END_ALIGNMENT_OPTION_NAME, END_ALIGNMENT_DEFAULT_VALUE, null,
			END_ALIGNMENT_OPTION_DESCRIPTION);

		options.registerOption(FORCE_MODEL_RELOAD_OPTION_NAME, FORCE_MODEL_RELOAD_DEFAULT_VALUE,
			null, FORCE_MODEL_RELOAD_OPTION_DESCRIPTION);

		options.registerOption(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME,
			ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT, null,
			ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESCRIPTION);

		options.registerOption(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME,
			ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT, null,
			ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESCRIPTION);

		options.registerOption(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME,
			SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT, null,
			SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		modelName = options.getString(MODELFILE_OPTION_NAME, MODEL_DEFAULT_NAME);
		setTrigramFileName(modelName);

		minStringLength = options.getEnum(MINIMUM_STRING_LENGTH_OPTION_NAME,
			MINIMUM_STRING_LENGTH_DEFAULT_VALUE).getMinLength();

		requireNullEnd = options.getBoolean(REQUIRE_NULL_TERMINATION_OPTION_NAME,
			REQUIRE_NULL_TERMINATION_DEFAULT_VALUE);

		startAlignment = options.getEnum(START_ALIGNMENT_OPTION_NAME,
			START_ALIGNMENT_DEFAULT_VALUE).getAlignment();

		setStringEndAlignment(
			options.getInt(END_ALIGNMENT_OPTION_NAME, END_ALIGNMENT_DEFAULT_VALUE));

		// Want to register "allCharWidths" property once we change this analyzer to be able to deal 
		// with UTF8, UTF16, UTF32 characters.
		//allCharWidths = options.registerProperty(ALL_CHAR_WIDTHS_OPTION_NAME, ALL_CHAR_WIDTHS_DEFAULT_VALUE, 
		//	ALL_CHAR_WIDTHS_OPTION_DESCRIPTION, null);

		forceModelReload =
			options.getBoolean(FORCE_MODEL_RELOAD_OPTION_NAME, FORCE_MODEL_RELOAD_DEFAULT_VALUE);

		allowStringCreationWithOffcutReferences =
			options.getBoolean(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME,
				ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT);

		allowStringCreationWithExistringSubstring =
			options.getBoolean(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME,
				ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT);

		searchOnlyAccessibleMemBlocks = options.getBoolean(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME,
			SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT);
	}

	private void setTrigramFileName(String name) {
		trigramFile = (name.endsWith(".sng")) ? name : (name + ".sng");
	}

	/**
	 * Determines if found ASCII strings are valid strings, and creates them if so.
	 * 
	 * @param program   program in which to search for strings
	 * @param addressSet  the address set to search
	 * @param minimumStringLength  the minimum length of strings to be returned
	 * @param alignVal	specifies any alignment requirements for the start of the string (valid
	 * 			values are 1, 2, or 4). An alignment of 1 means the string can start at any address.
	 * 			An alignment of 2 means	the string must start on an even address. An alignment of 4
	 * 			means the string must start on an address that is a multiple of 4. 
	 * @param requireNullTermination  if true, only strings that end in a null will be returned
	 * @param includeAllCharWidths	if true, UTF16 and UTF32 size strings will be included in 
	 * 			addition to UTF8
	 * @param monitor  monitor for this process
	 */
	private void findStrings(final Program program, AddressSetView addressSet,
			int minimumStringLength, int alignVal, boolean requireNullTermination,
			boolean includeAllCharWidths, TaskMonitor monitor) {

		FoundStringCallback foundStringCallback =
			foundString -> createStringIfValid(foundString, program, addressSet, monitor);

		StringSearcher searcher = new StringSearcher(program, minimumStringLength, alignVal,
			includeAllCharWidths, requireNullTermination);

		searcher.search(addressSet, foundStringCallback, true, monitor);
	}

}
