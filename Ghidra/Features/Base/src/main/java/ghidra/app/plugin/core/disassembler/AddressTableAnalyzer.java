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
package ghidra.app.plugin.core.disassembler;

import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.TaskMonitor;

/**
 * Check operand references to memory locations looking for Data
 */
public class AddressTableAnalyzer extends AbstractAnalyzer {
	private static String DESCRIPTION = "Analyzes undefined data for address tables.";

	private static final String OPTION_NAME_MIN_TABLE_SIZE = "Minimum Table Size";
	private static final String OPTION_NAME_TABLE_ALIGNMENT = "Table Alignment";
	private static final String OPTION_NAME_PTR_ALIGNMENT = "Pointer Alignment";
	private static final String OPTION_NAME_AUTO_LABEL_TABLE = "Auto Label Table";
	private static final String OPTION_NAME_MIN_POINTER_ADDR = "Minimum Pointer Address";
	private static final String OPTION_NAME_MAX_POINTER_DIFF = "Maxmimum Pointer Distance";
	private static final String OPTION_NAME_RELOCATION_GUIDE = "Relocation Table Guide";
	private static final String OPTION_NAME_ALLOW_OFFCUT_REFERENCES = "Allow Offcut References";

	protected static final String OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
	private static final String OPTION_DESCRIPTION_CREATE_BOOKMARKS =
		"If checked, an analysis bookmark will be created at each location where an address table is constructed.";
	private static final boolean OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

	private static final String OPTION_DESCRIPTION_MIN_TABLE_SIZE =
		"The minimum number of consecutive addresses that constitute an address table";
	private static final String OPTION_DESCRIPTION_TABLE_ALIGNMENT =
		"Only check for tables aligned to this number of bytes.";
	private static final String OPTION_DESCRIPTION_PTR_ALIGNMENT =
		"Only check for ptr table entries aligned to this number of bytes.";
	private static final String OPTION_DESCRIPTION_AUTO_LABEL_TABLE =
		"Label the start of the table and each entry as part of the table.";
	private static final String OPTION_DESCRIPTION_MIN_POINTER_ADDR =
		"Minimum Address that any value is considered a pointer";
	private static final String OPTION_DESCRIPTION_MAX_POINTER_DIFF =
		"Maximum distance in bytes between pointers before the table is broken up.";
	private static final String OPTION_DESCRIPTION_RELOCATION_GUIDE =
		"Select this check box to use relocation table entries to guide pointer analysis.";
	private static final String OPTION_DESCRIPTION_ALLOW_OFFCUT_REFERENCES =
		"Allow table entries that are offcut references to defined data or instructions.";

	private static final int OPTION_DEFAULT_TABLE_ALIGNMENT = 4;
	private static final int OPTION_DEFAULT_PTR_ALIGNMENT = 1;
	private static final boolean OPTION_DEFAULT_AUTO_LABEL_TABLE = false;
	private static final boolean OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED = true;
	private static final boolean OPTION_DEFAULT_ALLOW_OFFCUT_REFERENCES = false;
	private static final int OPTION_DEFAULT_MIN_POINTER_ADDR = 0x1024;
	private static final int OPTION_DEFAULT_MAX_POINTER_DIFF = 0xffffff;

	private int minimumTableSize = -1;
	private int tableAlignment = OPTION_DEFAULT_TABLE_ALIGNMENT;
	private int ptrAlignment = OPTION_DEFAULT_PTR_ALIGNMENT;
	private boolean autoLabelTable = OPTION_DEFAULT_AUTO_LABEL_TABLE;
	private boolean createBookmarksEnabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED;

	private long minPointerAddress = OPTION_DEFAULT_MIN_POINTER_ADDR;
	private long maxPointerDistance = OPTION_DEFAULT_MAX_POINTER_DIFF;

	private boolean relocationGuideEnabled = OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED;

	private boolean allowOffcutReferences = OPTION_DEFAULT_ALLOW_OFFCUT_REFERENCES;

	private boolean ignoreBookmarks = false;

	// true if the processor uses Address low bit to refer to code
	private boolean processorHasLowBitCode = false;

	public AddressTableAnalyzer() {
		super("Create Address Tables", DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
		setSupportsOneTimeAnalysis();

		// The analyzer should be off by default (as stated in its description)
		setDefaultEnablement(false);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// only analyze programs with address spaces > 16 bits
		int addrSize = program.getAddressFactory().getDefaultAddressSpace().getSize();
		// if processor uses the low bit to change instruction modes, then allow offcut refs
		processorHasLowBitCode = PseudoDisassembler.hasLowBitCodeModeInAddrValues(program);
		// don't align based on instruction start rules, data is important too.
		//   if do this, will miss, runs of ptrs to data/code/data/code/....
				// ptrAlignment = program.getLanguage().getInstructionAlignment();
				// if (processorHasLowBitCode) {
				// 	ptrAlignment = 1;
				// }
		return (addrSize == 32 || addrSize == 64);
	}

	@Override
	public boolean added(Program program, AddressSetView addrSet, TaskMonitor monitor,
			MessageLog log) {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		addrSet = removeNonSearchableMemory(program, addrSet);

		if (addrSet.isEmpty()) {
			ignoreBookmarks = false;
			return true;
		}

		long addrCount = program.getMemory().getNumAddresses();
		monitor.initialize(addrCount);
		monitor.setMessage("Analyze Address Tables");

		// iterate over addresses in the selectedmodule
		addrCount -= addrSet.getNumAddresses();

		Address minAddr = addrSet.getMinAddress();
		Address maxAddr = minAddr;

		// Iterate over all references within the new address set
		//   Evaluate each reference
		//

		AddressIterator addrIter = addrSet.getAddresses(true);

		while (addrIter.hasNext() && !monitor.isCancelled()) {
			addrCount++;
			monitor.setProgress(addrCount);
			Address start = addrIter.next();
			maxAddr = start;

			if (start.getOffset() % tableAlignment != 0) {
				continue;
			}

			if ((addrCount % 2048) == 1) {
				monitor.setMessage("Analyze Tables " + start);
			}
			AddressTable tableEntry =
				AddressTable.getEntry(program, start, monitor, true, minimumTableSize, ptrAlignment,
					0, AddressTable.MINIMUM_SAFE_ADDRESS, relocationGuideEnabled);
			if (tableEntry != null) {
				int tableLen = checkTable(tableEntry, program);
				if (tableLen < minimumTableSize) {
					continue;
				}

				Bookmark bookmark = program.getBookmarkManager().getBookmark(
					tableEntry.getTopAddress(), BookmarkType.ANALYSIS, "Address Table");

				// nothing to see here, already done.
				if (!ignoreBookmarks && bookmark != null) {
					// skip over this table, assumes the table is good as found...
					//   This is likely a good assumption, since the table analysis already did this area.
					Address nextAddr = start.add(tableEntry.getByteLength());
					addrIter = addrSet.getAddresses(nextAddr, true);
					maxAddr = nextAddr;
					continue;
				}

				// make the table
				tableEntry.makeTable(program, 0, tableLen - 1, autoLabelTable, false);

				Address startTable = tableEntry.getTopAddress();
				Address endTable = start.add(tableEntry.getByteLength());
				mgr.codeDefined(new AddressSet(startTable, endTable));

				// put info bookmark in
				if (createBookmarksEnabled) {
					program.getBookmarkManager().setBookmark(tableEntry.getTopAddress(),
						BookmarkType.ANALYSIS, "Address Table",
						"Address table[" + tableEntry.getNumberAddressEntries() + "] created");
				}

				// if all are valid code, disassemble
				List<Address> validCodeList = tableEntry.getFunctionEntries(program, 0);
				if (validCodeList != null &&
					validCodeList.size() >= tableEntry.getNumberAddressEntries()) {
					AddressSet validCodeSet = new AddressSet();
					AddressSet validFuncSet = new AddressSet();
					for (Address addr : validCodeList) {
						// set target context correctly. Target address will get
						// aligned in DisassembleCmd
						PseudoDisassembler.setTargeContextForDisassembly(program, addr);

						// even though they are valid code, don't do them if
						// there is already code there.
						if (program.getListing().getCodeUnitContaining(addr) == null) {
							validCodeSet.addRange(addr, addr);
						}
						// For Now, Never make functions from address tables,
						// Could later be an option
						// if (pdis.isValidSubroutine(addr, true)) {
						// validFuncSet.addRange(addr, addr);
						// }
					}
					// disassemble valid code
					if (!validCodeSet.isEmpty()) {
						mgr.disassemble(validCodeSet,
							AnalysisPriority.DATA_TYPE_PROPOGATION.before());
					}
					// if valid functions, schedule much later, so switch table analysis can pick it up.
					if (!validFuncSet.isEmpty()) {
						//  For Now, Never make functions from address tables, Could later be an option
						//		mgr.createFunction(validFuncSet, true,
						//		AnalysisPriority.DATA_TYPE_PROPOGATION.getNext());
					}
				}

				// jump the address iterator by the size of the table entry
				int tableByteLen = tableEntry.getByteLength(0, tableLen - 1, false);
				addrCount += tableByteLen;
				addrIter = skipBytes(addrIter, addrSet, start, tableByteLen);
				try {
					maxAddr = maxAddr.addNoWrap(tableByteLen - 1);
				}
				catch (AddressOverflowException e) {
					// pass
				}
				break;
			}
		} // end of while (addrIt.hasNext())

		// Set up a one time analysis to get us back into here if
		//   there are still addresses on the set
		//
		AddressSet set =
			addrSet.subtract(program.getAddressFactory().getAddressSet(minAddr, maxAddr));
		if (!set.isEmpty()) {
			mgr.scheduleOneTimeAnalysis(this, set);
		}
		else {
			// don't ignore address table bookmarks anymore
			ignoreBookmarks = false;
		}
		return true;
	}

	private AddressSetView removeNonSearchableMemory(Program program, AddressSetView addrSet) {
		// get rid of any non-initialized blocks
		ignoreBookmarks = ignoreBookmarks | addrSet.hasSameAddresses(program.getMemory());

		addrSet = addrSet.intersect(program.getMemory().getLoadedAndInitializedAddressSet());

		MemoryBlock[] blocks = program.getMemory().getBlocks();

		// get rid of any blocks that have empty attributes.
		//   Would be better to get rid of any blocks in a special RAWBytes address space, not overlays.
		//
		AddressSet badBlocks = new AddressSet();
		for (MemoryBlock memoryBlock : blocks) {
			if (memoryBlock.isWrite() || memoryBlock.isRead() || memoryBlock.isExecute() ||
				memoryBlock.isVolatile()) {
				continue;
			}

			badBlocks.addRange(memoryBlock.getStart(), memoryBlock.getEnd());
		}

		addrSet = addrSet.subtract(badBlocks);

		return addrSet;
	}

	/**
	 * @param tableEntry
	 * @param program
	 * @return number of entries in table before hitting entry that overlaps a string
	 */
	private int checkTable(AddressTable tableEntry, Program program) {
		// search for unicode strings first.
		//   don't create an address table that overlaps a unicode string.
		AddressSetView addrSet = tableEntry.getTableBody();
		AddressSet possibleStrings = findPossibleStrings(program, addrSet);

		// trim from the first offcut entry on
		Address start = tableEntry.getTopAddress();
		int tableLen = tableEntry.getNumberAddressEntries();
		Address addrs[] = tableEntry.getTableElements();
		for (int i = 0; i < tableLen; i++) {
			Address tableEntryAddr = start.add(i * 4);
			Address targetAddr = addrs[i];
			if (possibleStrings.contains(tableEntryAddr)) {
				return i;
			}
			if (possibleStrings.contains(tableEntryAddr.add(3))) {
				return i;
			}
			if ((tableEntryAddr.getOffset() > 0) &&
				tableEntryAddr.getOffset() < minPointerAddress) {
				return i;
			}
			// check that the table entries are not all over the place
			if (i > 0) {
				long diff = addrs[i - 1].subtract(addrs[i]);
				diff = Math.abs(diff);
				if (diff > maxPointerDistance) {
					return i;
				}
			}
			CodeUnit cu = program.getListing().getCodeUnitContaining(targetAddr);
			if (cu == null) {
				continue;
			}
			boolean atStartOfCU = cu.getMinAddress().equals(targetAddr);
			if (!allowOffcutReferences && !atStartOfCU) {
				// if the processor uses low bit to reference instructions
				//  allow offcut to an instruction by 1
				if (!processorHasLowBitCode || !(cu instanceof Instruction)) {
					return i;
				}
			}
		}
		return tableLen;
	}

	private AddressSet findPossibleStrings(Program program, AddressSetView addrSet) {
		AddressSet possibleStrSet = new AddressSet();
		Memory memory = program.getMemory();

		AddressIterator addrIter = addrSet.getAddresses(true);
		long maxBytes = addrSet.getNumAddresses();
		
		MemoryBufferImpl buffer = new MemoryBufferImpl(memory, addrSet.getMinAddress(), (int) (maxBytes > 1024 ? 1024 : maxBytes));

		while (addrIter.hasNext()) {
			Address start = addrIter.next();

			// skip over anything that smells like a unicode string
			//
			int strLen = getWStrLen(buffer, start, (int)(maxBytes / 2));
			if (strLen > 4) {
				int numBytes = strLen * 2;
				addrIter = skipBytes(addrIter, addrSet, start, numBytes);
				possibleStrSet.addRange(start, start.add(numBytes));
				continue;
			}
		}
		return possibleStrSet;
	}

	private AddressIterator skipBytes(AddressIterator iter, AddressSetView addrSet, Address start,
			int numBytes) {
		try {
			start = start.addNoWrap(numBytes);
		}
		catch (AddressOverflowException e) {
			return iter;
		}
		iter = addrSet.getAddresses(start, true);
		return iter;
	}

	/**
	 * getWStrLen
	 * @param ad = address where unicode string is supposed to begin
	 * @return number of unicode chars in string, -1 if not
	 * a unicode string.  NOTE: Only English strings are considered.
	 *
	 */
	private int getWStrLen(MemoryBufferImpl memory, Address ad, int max) {
		int i = 0;
		memory.setPosition(ad);
		try {
			for (i = 0; i < max; i++) {
				short value = memory.getShort(2 * i);
				if (value == 0) {
					return i + 1;
				}
				// allow tab, carriage return, and linefeed
				if (value != 0x09 && value != 0x0a && value != 0x0d &&
					(value < 0x20 || value >= 0x7f)) {
					return i;
				}
			}
		}
		catch (MemoryAccessException e) {
			return i;
		}
		return i;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) {
		return false;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// a probability calculation to decide to enable based on memory block bytes

		if (minimumTableSize == -1) {
			calculateMinimumTableSize(program);
		}

		return minimumTableSize != AddressTable.TOO_MANY_ENTRIES;
	}

	private void calculateMinimumTableSize(Program program) {
		minimumTableSize =
			AddressTable.getThresholdRunOfValidPointers(program, AddressTable.BILLION_CASES);

		if (minimumTableSize < 2) {
			minimumTableSize = 2;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_MIN_TABLE_SIZE, minimumTableSize, null,
			OPTION_DESCRIPTION_MIN_TABLE_SIZE);

		options.registerOption(OPTION_NAME_TABLE_ALIGNMENT, tableAlignment, null,
			OPTION_DESCRIPTION_TABLE_ALIGNMENT);

		options.registerOption(OPTION_NAME_PTR_ALIGNMENT, ptrAlignment, null,
			OPTION_DESCRIPTION_PTR_ALIGNMENT);

		options.registerOption(OPTION_NAME_AUTO_LABEL_TABLE, autoLabelTable, null,
			OPTION_DESCRIPTION_AUTO_LABEL_TABLE);

		options.registerOption(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled, null,
			OPTION_DESCRIPTION_RELOCATION_GUIDE);

		options.registerOption(OPTION_NAME_ALLOW_OFFCUT_REFERENCES, allowOffcutReferences, null,
			OPTION_DESCRIPTION_ALLOW_OFFCUT_REFERENCES);

		options.registerOption(OPTION_NAME_MIN_POINTER_ADDR, minPointerAddress, null,
			OPTION_DESCRIPTION_MIN_POINTER_ADDR);

		options.registerOption(OPTION_NAME_MAX_POINTER_DIFF, maxPointerDistance, null,
			OPTION_DESCRIPTION_MAX_POINTER_DIFF);

		options.registerOption(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled, null,
			OPTION_DESCRIPTION_CREATE_BOOKMARKS);

		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		if (minimumTableSize == -1) {
			calculateMinimumTableSize(program);
		}

		minimumTableSize = options.getInt(OPTION_NAME_MIN_TABLE_SIZE, minimumTableSize);

		tableAlignment = options.getInt(OPTION_NAME_TABLE_ALIGNMENT, tableAlignment);

		ptrAlignment = options.getInt(OPTION_NAME_PTR_ALIGNMENT, ptrAlignment);
		autoLabelTable = options.getBoolean(OPTION_NAME_AUTO_LABEL_TABLE, autoLabelTable);

		relocationGuideEnabled =
			options.getBoolean(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled);

		allowOffcutReferences =
			options.getBoolean(OPTION_NAME_ALLOW_OFFCUT_REFERENCES, allowOffcutReferences);

		minPointerAddress = options.getLong(OPTION_NAME_MIN_POINTER_ADDR, minPointerAddress);

		maxPointerDistance = options.getLong(OPTION_NAME_MAX_POINTER_DIFF, maxPointerDistance);

		createBookmarksEnabled =
			options.getBoolean(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled);

	}
}
